import argparse
import os
import sys
from cryptography.fernet import Fernet

# Function to load the encryption key from a file
def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("First do the setup.")
        return None  # Optionally return None or handle the error as needed

# Function to encrypt a log entry
def encrypt_entry(entry, key):
    cipher_suite = Fernet(key)
    encrypted_entry = cipher_suite.encrypt(entry.encode())
    return encrypted_entry.decode()

# Function to authenticate users based on the token in the log file
def authenticate(log, auth_token, key):
    if os.path.exists(log):
        with open(log, 'r') as f:
            encrypted_token = f.readline().strip()
            cipher_suite = Fernet(key)
            correct_token = cipher_suite.decrypt(encrypted_token.encode()).decode()
            return correct_token == auth_token
    else:
        raise FileNotFoundError("File with the name provided does not exist. Make sure you have done the setup first.")
    
# Function to append a new log entry (encrypted)
def append_log(log, timestamp, entry, key):
    try:
        encrypted_entry = encrypt_entry(f"{timestamp}, {entry}", key)
        with open(log, 'a') as f:
            f.write(encrypted_entry + "\n")
    except Exception as e:
        print("Error appending log entry.")

# Function to check the log state for consistency and last entry status
def validate_log(log, timestamp, user, key):
    if not os.path.exists(log):
        return True, None  # If the log does not exist, it's valid
    
    cipher_suite = Fernet(key)
    with open(log, 'r') as f:
        lines = f.readlines()[1:]  # Skip the first line (token)
        last_event_info = None
        last_timestamp = -1

        # Find the last log entry for the specified user
        for line in lines:
            decrypted_entry = cipher_suite.decrypt(line.strip().encode()).decode()
            entry = decrypted_entry.split(", ")
            if len(entry) >= 5:  # Ensure sufficient entry length
                event_timestamp = int(entry[0])
                if event_timestamp > last_timestamp:
                    last_timestamp = event_timestamp # Update the last timestamp found
                if entry[2] == user:
                    last_event_info = (entry[3], entry[4])  # (event type, room)
        # Ensure the new timestamp is greater than the last timestamp
        if int(timestamp) <= last_timestamp:
            return False, None
        return True, last_event_info  # If found, return last event info

# Function to handle batch file processing
def process_batch_file(batch_file):
    if not os.path.exists(batch_file):
        print("invalid: Batch file does not exist.")
        sys.exit(255)
    
    with open(batch_file, 'r') as f:
        line_number = 0  # Track line numbers for better error reporting
        for line in f:
            line_number += 1
            args = line.strip().split()
            if args:
                log_file = args[-1]  # Get the log file from the last argument
                try:
                    process_args(args[:-1] + [log_file])  # Process the current line
                except Exception as e:
                    print(f"Error processing line {line_number}: {e}")  # Print error and continue

# Main function to process command-line arguments and append log entry
def process_args(args=None):
    parser = argparse.ArgumentParser(description="Append new log entry.")
    
    # Command-line arguments
    parser.add_argument("-T", required=True, type=int, help="Timestamp for the event")
    parser.add_argument("-K", required=True, help="Authentication token")
    parser.add_argument("-E", help="Employee name")
    parser.add_argument("-G", help="Guest name")
    parser.add_argument("-A", action="store_true", help="Arrival event")
    parser.add_argument("-L", action="store_true", help="Departure event")
    parser.add_argument("-R", type=str, help="Room ID")
    parser.add_argument("log", help="Path to the log file")

    # Parse the arguments
    args = parser.parse_args(args)

    # Ensure the timestamp is not zero
    if args.T == 0:
        raise ValueError("Timestamp cannot be zero.")
    
    # Ensure only one of -E or -G is specified
    if (args.E and args.G) or (not args.E and not args.G):
        raise ValueError("Specify either -E for employee or -G for guest, not both.")
    
    # Ensure only one of -A or -L is specified
    if not (args.A or args.L):
        raise ValueError("One of -A (arrival) or -L (departure) must be specified.")
        
    if args.A and args.L:
        raise ValueError("Specify either -A for arrival or -L for departure, not both.")

    # Load encryption key
    key = load_key()
    if key is None:
        return  # Exit if key loading failed
    key = 'cjwLeVHhTx7PWUEGJVpYiPVRDUrPORnupX7TZED7w/Q='

    # Authenticate based on the token in the log file
    try:
        if not authenticate(args.log, args.K, key):
            raise ValueError("Authentication failed.")
    except FileNotFoundError:
        print("Log file does not exist. Please run setup first.")
        return  # Exit the function after printing the message

    # Validate log and get the last event for this user
    user = args.E if args.E else args.G
    is_valid, last_event = validate_log(args.log, args.T, user, key)

    if not is_valid:
        raise ValueError("Invalid log state.")

    if last_event:
        last_event_type, last_room = last_event[0], last_event[1]
        if last_event_type == 'arrival':
            current_room = last_room
        elif last_event_type == 'departure' and last_room != 'campus':
            current_room = 'campus'
        else:
            current_room = 'None'
    else:
        current_room = 'None'

    # Check entry and exit restrictions
    is_allowed, error_message = check_entry_exit_restrictions(current_room, args)
    if not is_allowed:
        raise ValueError(error_message)

    # Construct the log entry
    if args.E:
        name = args.E
        user_type = "employee"
    else:
        name = args.G
        user_type = "guest"

    event = f"{user_type}, {name}, {'arrival' if args.A else 'departure'}, {args.R if args.R is not None else 'campus'}"

    # Append the log (encrypted)
    append_log(args.log, args.T, event, key)
    print("Log entry added successfully.")



def check_entry_exit_restrictions(current_room, args):
    if args.A:  # Arrival event
        if current_room == 'None' and args.R is None:
            return True, None
        if current_room == 'campus' and args.R is not None:
            return True, None
        if current_room != 'campus' and args.R is not None:
            return False, "invalid: Are you on campus? You must leave the room first before entering another room."
        if current_room != 'campus' and args.R is None:
            return False, "invalid: You are in a room. First leave the room."
        if current_room == 'campus' and args.R is None:
            return False, "invalid: Already on campus."
       
    elif args.L:  # Departure event
        if current_room == 'campus' and args.R is None:
            return True, None
        if current_room != 'campus' and args.R is None:
            return False, "invalid: Either first leave the room or You have already left the campus."
        if current_room == args.R and args.R is not None:
            return True, None
        if current_room != 'campus' and args.R is not None:
            return False, "invalid: Leave the room you are in first."
        if current_room != args.R and args.R is not None:
            return False, "invalid: Must have been in the room to leave it."
    
    return True, None

# Entry point for the script
if __name__ == "__main__":
    try:
        # Check for batch mode
        if "-B" in os.sys.argv:
            batch_index = os.sys.argv.index("-B") + 1
            batch_file = os.sys.argv[batch_index]
            process_batch_file(batch_file)
        else:
            process_args()   
    except Exception as e:
        print(f"Error: {str(e)}")  # Print only the error message
