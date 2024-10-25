import sys
import os
import re
from cryptography.fernet import Fernet
import bcrypt

# Define reserved flags globally
reserved_flags = {"-T", "-K", "-A", "-L", "-E", "-G", "-R", "-B", "-S", "-R", "-T", "-I"}

def is_valid_password(password):
    # Ensure password does not contain hyphens and is not a reserved flag
    return '-' not in password and password not in reserved_flags

def is_valid_filename(filename):
    # Check if the filename is alphanumeric (with underscores and periods allowed) and not only periods
    return re.match(r'^[\w.]+$', filename) is not None and not all(char == '.' for char in filename)

def main():
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python setup.py <password> <log_file>")
        sys.exit(1)

    # Get password and log file name from arguments
    password = sys.argv[1]
    log_file = sys.argv[2]

    # Validate password and log file name
    if not is_valid_password(password):
        print("Invalid password: hyphens are not allowed in passwords.")
        sys.exit(1)
    if not is_valid_filename(log_file):
        print("Invalid log file name: must be alphanumeric.")
        sys.exit(1)

    print(f"Arguments received: {sys.argv[1:]}")  # Debugging statement

    # Check if the log file already exists and has been set up
    if os.path.exists(log_file) and os.path.exists('secret.key'):
        print(f"Setup for {log_file} has already been done. Cannot set up again.")
        return  # Exit if the log file has already been set up

    # Generate or read the secret key for Fernet encryption
    key_file = 'secret.key'
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
            print(f"Using existing key from {key_file}.")  # Debugging statement
    except FileNotFoundError:
        print("Secret key not found. Generating a new one.")
        key = Fernet.generate_key()
        with open(key_file, 'wb') as kf:
            kf.write(key)
            print(f"New key generated and saved to {key_file}.")  # Debugging statement

    # Create a Fernet object with the key (for future encryption use)
    f = Fernet(key)

    # Hash the password using bcrypt
    salt = bcrypt.gensalt()  # Generate a salt for hashing
    hashed_password = bcrypt.hashpw(password.encode(), salt)  # Hash the password with bcrypt
    
    # Save the hashed password to the specified log file
    with open(log_file, 'ab') as lf:  # Append to the file
        lf.write(hashed_password + b'\n')  # Add a newline for clarity
    
    print("Setup Done. Remember Your Password.")
    
if __name__ == "__main__":
    main()
