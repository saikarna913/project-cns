from fastapi import FastAPI, Depends, Body, Request
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String, Numeric, select
from pydantic import BaseModel
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer
import jwt
from banking_system.key import generate_secret_key
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from passlib.context import CryptContext
import logging

PRINT_LEVEL_NUM = 25
logging.addLevelName(PRINT_LEVEL_NUM, "PRINT")

def print_log(self, message, *args, **kws):
    if self.isEnabledFor(PRINT_LEVEL_NUM):
        self._log(PRINT_LEVEL_NUM, message, args, **kws)

logging.Logger.print = print_log
logger = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
# JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
JWT_SECRET_KEY = generate_secret_key()
JWT_ALGORITHM = "HS256"

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    pbkdf2_sha256__default_rounds=30000
)

class ApplicationException(Exception):
    def __init__(self):
        super().__init__()

# Create an asynchronous engine for the database
engine = create_async_engine(DATABASE_URL, echo=False)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

limiter = Limiter(key_func=get_remote_address)

# Set up a sessionmaker to create database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession
)

Base = declarative_base()

class Account(Base):
  __tablename__ = "accounts"

  id = Column(Integer, primary_key=True, index=True)
  account_name = Column(String(122), index=True, unique=True)
  balance = Column(Numeric(precision=12, scale=2), nullable=False, default=10.0)
  card_number = Column(String(187), unique=True, index=True)
  pin = Column(String)

class SessionData(Base):
    __tablename__ = "session_data"
    account_name = Column(String(122), primary_key=True)
    token = Column(String)

class transaction(BaseModel):
    amount: str
    account_name: str
    card_number: str
#! needs auth file here (imp)

async def get_db():
    async with SessionLocal() as session:
        yield session

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda request, exc: JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}))
app.add_middleware(SlowAPIMiddleware)

#setting up middleware to reject http requests
@app.middleware("http")
async def reject_http_middleware(request: Request, call_next):
    if request.url.scheme == "http":
        raise HTTPException(status_code=403, detail="HTTP requests are forbidden. Please use HTTPS.")

    response = await call_next(request)
    return response

def create_access_token(data: dict):
    to_encode = data.copy()
    expiry = datetime.now(timezone.utc) + timedelta(seconds=60)
    to_encode.update({"exp": expiry})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def validate_token(data: transaction, token: str, db: AsyncSession):
    try:
        # A simple check before decoding the token if the user has logged out or not (no entry in the db)
        session_data = await db.execute(select(SessionData).filter(SessionData.account_name == data.account_name))
        data_entry = session_data.scalars().first()
        if not data_entry or data_entry.token != token:
            raise ApplicationException()

        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_exp": True})

        if not payload.get("account_name") or data.account_name != payload.get("account_name"):
            raise ApplicationException()

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except ApplicationException:
        raise HTTPException(status_code=401, detail="Invalid data")
    except Exception as e:
        raise HTTPException(status_code=401, detail=e)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.commit()
    
    logger.print("Application started and ready to recieve requests.")

@app.get("/")
@limiter.limit("7/second")
async def read_root(request: Request,db: AsyncSession = Depends(get_db)):
    return {"message": "Connected to PostgreSQL database successfully!"}

class AccountCreate(BaseModel):
    account_name: str
    card_number: str
    balance: str
    pin: str

@app.post("/create")
@limiter.limit("7/second")
async def create_account(request: Request, account: AccountCreate = Body(...), db: AsyncSession = Depends(get_db)):
    existing_account = await db.execute(select(Account).filter((Account.account_name == account.account_name) | (Account.card_number == account.card_number)))

    if existing_account.scalars().first():
        return {"message": "Account with this name or card number already exists", "status": "exists"}

    db_account = Account(
        account_name=account.account_name,
        card_number=account.card_number,
        balance=Decimal(account.balance).quantize(Decimal('0.01'), rounding='ROUND_DOWN'),
        pin=pwd_context.encrypt(account.pin)
    )
    db.add(db_account)
    await db.commit()
    logger.print({"account": account.account_name, "initial_balance": account.balance})
    return {"message": "Account created successfully", "status": "success"}

async def db_check(data, db: AsyncSession):
    session_data = await db.execute(select(SessionData).filter(SessionData.account_name == data.account_name))
    session_data = session_data.scalars().first()
    if session_data:
        try:
            payload = jwt.decode(session_data.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_exp": True})
            raise ApplicationException()
        except jwt.ExpiredSignatureError:
            await db.delete(session_data)
            await db.commit()
            return {"message": "expired"}
        except ApplicationException:
            raise HTTPException(status_code=401, detail="Multiple sessions not allowed")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

class LoginDetails(BaseModel):
    account_name: str
    card_number: str
    pin: str

@app.post("/login")
@limiter.limit("7/second")
async def login(request: Request, data: LoginDetails = Body(...), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Account).filter(Account.account_name == data.account_name))
    account = result.scalars().first()
    if account:
        if account.card_number == data.card_number and pwd_context.verify(data.pin, account.pin):
            await db_check(data, db)
            access_token = create_access_token({"account_name": data.account_name})
            db.add(SessionData(account_name=data.account_name, token=access_token))
            await db.commit()
            return {"message": "Login successful", "token": access_token, "status": 1}
        else:
            return {"message": "Invalid card number or pin", "status": 0}
    else:
        return {"message": "Account not found", "status": -1}

class Balance(BaseModel):
    account_name: str
    card_number: str

@app.post("/logout")
@limiter.limit("7/second")
async def logout(request: Request,data: Balance = Body(...), db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    result = await db.execute(select(Account).filter(Account.account_name == data.account_name))
    account = result.scalars().first()
    if account:
        if account.card_number == data.card_number:
            result = await db.execute(select(SessionData).filter(SessionData.account_name == data.account_name))
            session_data = result.scalars().first()
            if session_data:
                await db.delete(session_data)
                await db.commit()
                return {"message": "Logout successful", "status": 1}
            else:
                return {"message": "Session not found", "status": -1}
        else:
            return {"message": "Invalid card number or pin", "status": 0}
    else:
        return {"message": "Account not found", "status": -2}

@app.post("/withdraw")
@limiter.limit("7/second")
async def withdraw(request: Request,data: transaction = Body(...), db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    await validate_token(data, token, db)
    if Decimal(data.amount) <= 0:
        return {"message": "Invalid amount", "status": -2}
    result = await db.execute(select(Account).filter(Account.account_name == data.account_name))
    account = result.scalars().first()
    if account:
        if account.card_number == data.card_number:
            if account.balance < Decimal(data.amount).quantize(Decimal('0.01'), rounding='ROUND_DOWN'):
                return {"message": "Insufficient funds", "status": -2}
            account.balance -= Decimal(data.amount).quantize(Decimal('0.01'), rounding='ROUND_DOWN')
            await db.commit()
            await db.refresh(account)
            logger.print(f'{{"account": {account.account_name}, "withdraw": {Decimal(data.amount)}}}')
            return {"message": "Withdrawal successful", "status": 1}
        else:
            return {"message": "Invalid card number or pin", "status": 0}
    else:
        return {"message": "Account not found", "status": -1}

@app.post("/deposit")
@limiter.limit("7/second")
async def deposit(request: Request,data: transaction = Body(...), db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    await validate_token(data, token, db)
    if Decimal(data.amount) <= 0 or Decimal(data.amount) >= 4294967296:
        return {"message": "Invalid amount", "status": -2}
    result = await db.execute(select(Account).filter(Account.account_name == data.account_name))
    account = result.scalars().first()
    if account:
        if account.card_number == data.card_number:
            account.balance += Decimal(data.amount).quantize(Decimal('0.01'), rounding='ROUND_DOWN')
            await db.commit()
            await db.refresh(account)
            logger.print(f'{{"account": {account.account_name}, "deposit": {Decimal(data.amount)}}}')
            return {"message": "Deposit successful", "status": 1}
        else:
            return {"message": "Invalid card number or pin", "status": 0}
    else:
        return {"message": "Account not found", "status": -1}

@app.post("/balance")
@limiter.limit("7/second")
async def get_balance(request: Request,data: Balance = Body(...), db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    await validate_token(data, token, db)
    result = await db.execute(select(Account).filter(Account.account_name == data.account_name))
    account = result.scalars().first()
    if account:
        if account.card_number == data.card_number:
            logger.print(f'{{"account": {account.account_name}, "balance": {account.balance}}}')
            return {"message": account.balance, "status": 1}
        else:
            return {"message": "Invalid card number or pin", "status": 0}
    else:
        return {"message": "Account not found", "status": -1}

# Global exception handler for generic exceptions
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred."},
    )

# Global exception handler for HTTP exceptions
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # logger.print(exc.status_code, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
