import re
import uuid
import hashlib
import ipaddress

def validate_parameters(auth_file, ip_address, port, card_file, account, pin):
    # Validate file names (auth_file and card_file)
    file_name_pattern = re.compile(r'^[a-z0-9_.-]{1,127}$')
    if auth_file is not None and not file_name_pattern.match(auth_file) or auth_file in [".", ".."]:
        return False, "Invalid auth_file name"
    if card_file is not None and not file_name_pattern.match(card_file) or card_file in [".", ".."]:
        return False, "Invalid card_file name"

    # Validate account names
    account_name_pattern = re.compile(r'^[a-z0-9_.-]{1,127}$')
    if not account_name_pattern.match(account):
        return False, "Invalid account name"

    # Validate IP address
    try:
        ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return False, "Invalid IP address"

    # Validate port
    if not (1024 <= port <= 65535):
        return False, "Invalid port number"

    # Validate pin
    pin_pattern = re.compile(r'^\d{4,8}$')
    if pin is not None and not pin_pattern.match(pin):
        return False, "Invalid pin"

    return True, "All parameters are valid"

def generate_card_number(account_name):
    # Generate a UUID
    unique_id = uuid.uuid4().hex

    # Create a hash of the account name and UUID
    hash_input = f"{account_name}{unique_id}".encode('utf-8')
    card_hash = hashlib.sha256(hash_input).hexdigest()

    # Combine the account name and hash to create a unique card number
    card_number = f"{account_name}:{card_hash}"

    return card_number

# Test usage
if __name__ == "__main__":
    auth_file = "valid_auth1_file.ext"
    ip_address = "192.168.1.1"
    port = 8080
    card_file = "valid_card2_file.card"
    account = "valid_account00"
    pin = "123456"

    is_valid, message = validate_parameters(auth_file, ip_address, port, card_file, account, pin)
    print(message)

    print(generate_card_number(account))
    print(generate_card_number("valid_account001"))
    print(generate_card_number("valid_account00463765"))