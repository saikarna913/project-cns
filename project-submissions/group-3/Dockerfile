FROM python:3.10-slim

RUN pip install poetry

WORKDIR /app

COPY pyproject.toml ./

RUN poetry install --no-root

COPY . .

EXPOSE ${SERVER_PORT}

# CMD ["poetry", "run", "uvicorn", "banking_system.bank:app", "--host", "0.0.0.0", "--port", "$SERVER_PORT", "--reload"]
# CMD poetry run uvicorn banking_system.bank:app --host 0.0.0.0 --port $SERVER_PORT --reload
# COPY script.sh /usr/local/bin/script.sh
# RUN chmod +x /usr/local/bin/script.sh
# CMD ["/usr/local/bin/script.sh"]

# RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -config openssl.cnf
# CMD cp ./cert.pem /tmp && poetry run uvicorn banking_system.bank:app --host 0.0.0.0 --port ${SERVER_PORT} --ssl-keyfile=key.pem --ssl-certfile=cert.pem 
CMD cp ./cert.pem /tmp && poetry run uvicorn banking_system.bank:app --host 0.0.0.0 --port ${SERVER_PORT} --ssl-keyfile=key.pem --ssl-certfile=cert.pem --log-config logging_config.yaml