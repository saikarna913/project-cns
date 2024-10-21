import click
import json
import os
import sys
import requests
import random
import traceback
import sanity
from typing import Dict, Any
from decimal import Decimal, ROUND_DOWN

certificate_path = "certs/cert.pem"
cards_directory = "cards"
auth_directory = "auth"
os.makedirs(cards_directory, exist_ok=True)
os.makedirs(auth_directory, exist_ok=True)

def validate_account(ctx, param, value):
    if not value or not value.isdigit() or len(value) != 5:
        raise click.BadParameter("Account must be a 5-digit number")
    return value

def read_card_file(card_file: str) -> Dict[str, str]:
    try:
        with open(card_file, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        click.echo("Error: Unable to read card file", err=True)
        sys.exit(255)

def create_card_file(account: str, card_number: str, pin: str, card_file: str) -> bool:
    try:
        with open(card_file, 'w') as f:
            json.dump({"account": account, "card_number": card_number, "pin": pin}, f)
        return True
    except IOError:
        click.echo("Error: Unable to create card file", err=True)
        sys.exit(255)

def verify_pin(account: str, card_file: str, ip_address: str, port: int) -> Dict[str, str]:
    card_data = read_card_file(card_file)
    pin = click.prompt("Enter your 4-digit PIN", hide_input=True)

    response = communicate_with_bank("verify_pin", {
        "account": account,
        "card_number": card_data["card_number"],
        "pin": pin
    }, ip_address, port)

    if response and response.get("verified", False):
        return card_data
    else:
        click.echo("PIN verification failed.", err=True)
        sys.exit(255)

def communicate_with_bank(endpoint: str, data: Dict[str, Any], ip_address: str, port: int, token: str = None) -> Dict[str, Any]:
    try:
        if token:
            headers = {
                "Authorization": f"Bearer {token}"
            }
            response = requests.post(f"https://{ip_address}:{port}/{endpoint}", json=data, headers=headers, verify=certificate_path)
        else:
            response = requests.post(f"https://{ip_address}:{port}/{endpoint}", json=data, verify=certificate_path)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        exit_code = 63
        try:
            error_detail = e.response.json().get("detail", str(e))
            exit_code = 255
        except (ValueError, AttributeError):
            error_detail = str(e)
        click.echo(f"Error communicating with bank: {error_detail}", err=True)
        sys.exit(exit_code)

def read_auth_file(auth_file: str, account: str) -> Dict[str, Any]:
    auth_file_path = os.path.join(auth_directory, f"{auth_file}#{account}.auth")
    try:
        with open(auth_file_path, 'r') as f:
            return json.load(f)
    except IOError as e:
        click.echo(f"Error reading auth file: {str(e)}", err=True)
        sys.exit(255)

def update_auth_file(auth_file: str, account: str, data: Dict[str, Any]) -> None:
    auth_file_path = os.path.join(auth_directory, f"{auth_file}#{account}.auth")
    try:
        with open(auth_file_path, 'w') as f:
            json.dump(data, f)
    except IOError as e:
        click.echo(f"Error updating auth file: {str(e)}", err=True)
        sys.exit(255)

def create_account(account_name: str, card_number: str, pin: str, balance: Decimal, ip_address: str, port: int):
    if balance < 10.00:
        click.echo("Error: Invalid initial balance", err=True)
        sys.exit(255)
    if balance >= 4294967296:
        click.echo("Error: Initial amount exceeds the maximum limit", err=True)
        sys.exit(255)

    # Check for more than 2 decimal places
    if balance.as_tuple().exponent < -2:
        click.echo("Warning: Only 2 decimal places are supported. Truncating amount.", err=True)
        balance = balance.quantize(Decimal('0.01'), rounding=ROUND_DOWN)

    # Creation of JSON data for sending to server
    data = {
        "account_name": account_name,
        "balance": str(balance),
        "card_number": card_number,
        "pin": pin
    }

    # Sending the data to the servering and parsing the response
    response = communicate_with_bank("create", data, ip_address, port)
    if (response):
        if (response["status"] == "success"):
            click.echo("Account created successfully")
            print({"account": account_name, "initial-balance": format(balance, ".2f")})
        else:
            # Account already exists
            click.echo(response["message"], err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Account creation failed", err=True)
        sys.exit(255)

def account_login(account_name: str, card_number: str, pin: str, auth_file: str, ip_address: str, port: int):
    data = {
        "account_name": account_name,
        "card_number": card_number,
        "pin": pin
    }
    response = communicate_with_bank("login", data, ip_address, port)
    if (response):
        if (response["status"] == 1):
            update_auth_file(auth_file, account_name, response["token"])
            click.echo(click.style("Login successful", fg="green"))
        elif (response["status"] == 0):
            click.echo("Login failed, invalid card number or pin", err=True)
            sys.exit(255)
        else:
            click.echo("ERROR: Account not found", err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Login failed", err=True)
        sys.exit(255)

def make_deposit(account_name: str, card_number: str, amount: Decimal, auth_file: str, ip_address: str, port: int):
    if amount <= 0.00:
        click.echo("Error: Invalid deposit amount", err=True)
        sys.exit(255)
    if amount >= 4294967296:
        click.echo("Error: Deposit amount exceeds the maximum limit", err=True)
        sys.exit(255)

    # Check for more than 2 decimal places
    if amount.as_tuple().exponent < -2:
        click.echo("Warning: Only 2 decimal places are supported. Truncating amount.", err=True)
        amount = amount.quantize(Decimal('0.01'), rounding=ROUND_DOWN)

    auth_token = read_auth_file(auth_file, account_name)
    data = {
        "account_name": account_name,
        "card_number": card_number,
        "amount": str(amount)
    }

    response = communicate_with_bank("deposit", data, ip_address, port, auth_token)
    if (response):
        if (response["status"] == 1):
            click.echo("Deposit successful")
            click.echo({"account": account_name, "deposit": format(amount, ".2f")})
        elif (response["status"] == 0):
            click.echo("Wrong credentials", err=True)
            sys.exit(255)
        elif (response["status"] == -2):
            click.echo("Amount exceeds the limit", err=True)
            sys.exit(255)
        else:
            click.echo("ERROR: Account not found", err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Deposit failed", err=True)
        sys.exit(255)

def make_withdrawal(account_name: str, card_number: str, amount: Decimal, auth_file: str, ip_address: str, port: int):
    if amount <= 0.00:
        click.echo("Error: Invalid withdrawal amount", err=True)
        sys.exit(255)

    # Check for more than 2 decimal places
    if amount.as_tuple().exponent < -2:
        click.echo("Warning: Only 2 decimal places are supported. Truncating amount.", err=True)
        amount = amount.quantize(Decimal('0.01'), rounding=ROUND_DOWN)

    auth_token = read_auth_file(auth_file, account_name)
    data = {
        "account_name": account_name,
        "card_number": card_number,
        "amount": str(amount)
    }
    response = communicate_with_bank("withdraw", data, ip_address, port, auth_token)
    if (response):
        if (response["status"] == 1):
            click.echo("Withdrawal successful")
            click.echo({"account": account_name, "withdraw": format(amount, ".2f")})
        elif (response["status"] == 0):
            click.echo("Wrong credentials", err=True)
            sys.exit(255)
        elif (response["status"] == -2):
            click.echo("Insufficient balance", err=True)
            sys.exit(255)
        else:
            click.echo("ERROR: Account not found", err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Withdrawal failed", err=True)
        sys.exit(255)

def check_balance(account_name: str, card_number: str, auth_file: str, ip_address: str, port: int):
    auth_token = read_auth_file(auth_file, account_name)
    data = {
        "account_name": account_name,
        "card_number": card_number
    }
    response = communicate_with_bank("balance", data, ip_address, port, auth_token)
    if (response):
        if (response["status"] == 1):
            click.echo("Current Balance")
            click.echo({"account": account_name, "balance": response['message']})
        elif (response["status"] == 0):
            click.echo("Wrong credentials", err=True)
            sys.exit(255)
        else:
            click.echo("ERROR: Account not found", err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Balance check failed", err=True)
        sys.exit(255)

def account_logout(account_name: str, card_number: str, auth_file: str, ip_address: str, port: int):
    auth_file_path = os.path.join(auth_directory, f"{auth_file}#{account_name}.auth")
    if not os.path.exists(auth_file_path):
        click.echo(f"ERROR: Authentication file {auth_file} not found", err=True)
        sys.exit(255)

    data = {
        "account_name": account_name,
        "card_number": card_number,
    }
    auth_token = read_auth_file(auth_file, account_name)

    response = communicate_with_bank("logout", data, ip_address, port, auth_token)
    if (response):
        if (response["status"] == 1):
            if os.path.exists(auth_file):
                os.remove(auth_file)
            click.echo(click.style("Logout successful. Visit Again.", fg="green"))
        else:
            click.echo(response[ "message"], err=True)
            sys.exit(255)
    else:
        click.echo("ERROR: Logout failed", err=True)
        sys.exit(255)

@click.command()
@click.option('-s', '--auth-file', default='bank', help='Authentication file')
@click.option('-i', '--ip-address', default='127.0.0.1', help='Bank server IP address')
@click.option('-p', '--port', default=8000, type=int, help='Bank server port')
@click.option('-c', '--card-file', help='Customer\'s ATM card file')
@click.option('-a', '--account', required=True, help='Customer\'s account number')
@click.option('-n', '--new-account', type=Decimal, help='Initial balance for new account')
@click.option('-d', '--deposit', type=Decimal, help='Amount to deposit')
@click.option('-w', '--withdraw', type=Decimal, help='Amount to withdraw')
@click.option('-g', '--get-balance', is_flag=True, help='Get account balance')
@click.option('-l', '--login', is_flag=True, help='Login to account')
@click.option('-o', '--logout', is_flag=True, help='Logout from account')
def atm(auth_file, ip_address, port, card_file, account, new_account, deposit, withdraw, get_balance, login, logout):
    
    # Operation mode validation
    mode_count = sum(1 for mode in [new_account, deposit, withdraw, get_balance, login, logout] if mode)
    if mode_count != 1:
        click.echo("Error: Invalid combination of operation modes", err=True)
        sys.exit(255)

    # Ask for PIN
    pin = None
    if login or new_account is not None:
        pin = click.prompt("Please enter your PIN", hide_input=True)

    # Validate parameters
    is_valid, message = sanity.validate_parameters(auth_file, ip_address, port, card_file, account, pin)
    if not is_valid:
        click.echo(f"Error: {message}", err=True)
        sys.exit(255)

    # Verify auth file 
    if new_account is not None:
        if auth_file != "bank":
            click.echo("Warning: auth-file is not required for creating a new account", err=True)
    elif login:
        pass
        # if os.path.isfile(auth_file):
        #     click.echo(f"Error: Authentication file name {auth_file} is not available", err=True)
        #     sys.exit(255)
    else:
        auth_file_path = os.path.join(auth_directory, f"{auth_file}#{account}.auth")
        if not os.path.isfile(auth_file_path):
            click.echo("Error: Wrong authentication file", err=True)
            sys.exit(255)

    # Ping bank server
    try:
        response = requests.get(f"https://{ip_address}:{port}/", verify=certificate_path)
        response.raise_for_status()
    except requests.RequestException as e:
        click.echo(f"Error connecting to bank server: {str(e)}", err=True)
        sys.exit(63)

    if not card_file:
        card_file = str(account)
    card_file_path = os.path.join(cards_directory, f"{card_file}#{account}.card")

    if new_account is not None:
        # Check if the provided card file exists
        if os.path.exists(card_file_path):
            click.echo(f"Error: {card_file} card file already exists, try something else", err=True)
            sys.exit(255)
        # Create the card file and store the unique card number
        card_number = sanity.generate_card_number(account)
        with open(card_file_path, "w") as f:
            f.write(card_number)
    else:
        # Check if the card file exists in the cards directory
        if not os.path.exists(card_file_path):
            click.echo(f"Error: {card_file} does not exist", err=True)
            sys.exit(255)
        # Extract the card number and validate it
        with open(card_file_path, "r") as f:
            card_number = f.read().strip()
        if not card_number.startswith(f"{account}:"):
            click.echo("Error: Wrong card file", err=True)
            sys.exit(255)

    if new_account is not None:
        create_account(account, card_number, pin, Decimal(new_account), ip_address, port)
    elif login:
        account_login(account, card_number, pin, auth_file, ip_address, port)
    elif deposit is not None:
        make_deposit(account, card_number, Decimal(deposit), auth_file, ip_address, port)
    elif withdraw is not None:
        make_withdrawal(account, card_number, Decimal(withdraw), auth_file, ip_address, port)
    elif get_balance:
        check_balance(account, card_number, auth_file, ip_address, port)
    elif logout:
        account_logout(account, card_number, auth_file, ip_address, port)
    else:
        click.echo("Error: No operation specified", err=True)
        sys.exit(255)

def global_exception_handler(exc_type, exc_value, exc_traceback):
    # traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)
    print(f"{exc_type.__name__}", file=sys.stderr)
    sys.exit(255)

sys.excepthook = global_exception_handler

if __name__ == '__main__':
    atm()
