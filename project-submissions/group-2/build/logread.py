import argparse
import os
from cryptography.fernet import Fernet

# Function to load the encryption key from a file
def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("First do the setup")
        return None  # Optionally return None or handle the error as needed

# Function to decrypt a log entry
def decrypt_entry(entry, key):
    cipher_suite = Fernet(key)
    decrypted_entry = cipher_suite.decrypt(entry.encode())
    return decrypted_entry.decode()

# Function to authenticate the log based on the token
def authenticate(log, auth_token, key):
    if os.path.exists(log):
        with open(log, 'r') as f:
            encrypted_token = f.readline().strip()
            cipher_suite = Fernet(key)
            correct_token = cipher_suite.decrypt(encrypted_token.encode()).decode()
            return correct_token == auth_token
    else:
        print(f"Log file '{log}' does not exist.")
        return False

# Function to calculate total time spent by an employee/guest in the campus
def calculate_total_time(log, name, entity_type, key):
    total_time = 0
    in_campus = False
    last_arrival = None
    latest_timestamp = None

    try:
        with open(log, 'r') as f:
            lines = f.readlines()[1:]  # Skip the first line (token)
            for line in lines:
                decrypted_entry = decrypt_entry(line.strip(), key)
                parts = decrypted_entry.split(", ")
                timestamp = int(parts[0])
                entity = parts[1]
                person_name = parts[2]
                action = parts[3]
                room = parts[4] if len(parts) > 4 else "campus"

                # Update the latest timestamp
                latest_timestamp = timestamp

                if person_name == name and entity == entity_type:
                    if action == "arrival" and room == "campus":
                        # Mark arrival in campus
                        last_arrival = timestamp
                        in_campus = True
                    elif action == "departure" and room == "campus":
                        # Mark departure from campus and calculate time spent
                        if in_campus and last_arrival is not None:
                            total_time += timestamp - last_arrival
                            in_campus = False
                            last_arrival = None

        # If the person is still in the campus, calculate time till the latest timestamp
        if in_campus and last_arrival is not None:
            total_time += latest_timestamp - last_arrival

    except Exception as e:
        print(f"Error reading log file: {e}")

    return total_time

# Function to read the current state of the campus
def read_state(log, key):
    employees = []
    guests = []
    rooms = {}

    try:
        with open(log, 'r') as f:
            lines = f.readlines()[1:]  # Skip the first line (token)
            for line in lines:
                decrypted_entry = decrypt_entry(line.strip(), key)
                parts = decrypted_entry.split(", ")
                timestamp = int(parts[0])
                entity_type = parts[1]
                name = parts[2]
                action = parts[3]
                room = parts[4] if len(parts) > 4 else "campus"

                if action == "arrival":
                    if room == "campus":
                        if entity_type == "employee":
                            employees.append(name)
                        else:
                            guests.append(name)
                    else:
                        if room not in rooms:
                            rooms[room] = []
                        rooms[room].append(name)

                elif action == "departure":
                    if room == "campus":
                        if entity_type == "employee":
                            if name in employees:
                                employees.remove(name)
                        else:
                            if name in guests:
                                guests.remove(name)
                    else:
                        if room in rooms and name in rooms[room]:
                            rooms[room].remove(name)

    except Exception as e:
        print(f"Error reading log file: {e}")

    return employees, guests, rooms

# Function to print the current state of the campus
def print_state(employees, guests, rooms):
    print(",".join(sorted(employees)))
    print(",".join(sorted(guests)))
    for room_id in sorted(rooms.keys(), key=int):
        print(f"{room_id}: {','.join(sorted(rooms[room_id]))}")

# New function to list all rooms entered by an employee or guest
def list_rooms(log, name, entity_type, key):
    rooms_visited = []

    try:
        with open(log, 'r') as f:
            lines = f.readlines()[1:]  # Skip the first line (token)
            for line in lines:
                decrypted_entry = decrypt_entry(line.strip(), key)
                parts = decrypted_entry.split(", ")
                entity = parts[1]
                person_name = parts[2]
                action = parts[3]
                room = parts[4] if len(parts) > 4 else "campus"

                if person_name == name and entity == entity_type and action == "arrival" and room != "campus":
                    rooms_visited.append(room)
    except Exception as e:
        print(f"Error reading log file: {e}")

    return rooms_visited

# New function to list rooms occupied by all specified employees and guests at the same time
def list_common_rooms(log, names, key):
    room_occupancy = {}
    common_rooms = set()

    try:
        with open(log, 'r') as f:
            lines = f.readlines()[1:]  # Skip the first line (token)
            for line in lines:
                decrypted_entry = decrypt_entry(line.strip(), key)
                parts = decrypted_entry.split(", ")
                entity_type = parts[1]
                name = parts[2]
                action = parts[3]
                room = parts[4] if len(parts) > 4 else "campus"

                if action == "arrival" and room != "campus":
                    if room not in room_occupancy:
                        room_occupancy[room] = set()
                    room_occupancy[room].add(name)
                elif action == "departure" and room != "campus":
                    if room in room_occupancy and name in room_occupancy[room]:
                        room_occupancy[room].remove(name)

        for room, occupants in room_occupancy.items():
            if all(name in occupants for name in names):
                common_rooms.add(room)

    except Exception as e:
        print(f"Error reading log file: {e}")

    return sorted(common_rooms, key=int)

# Main function to process command-line arguments and query the log
def process_args(args=None):
    parser = argparse.ArgumentParser(description="Read campus log.")

    # Command-line arguments
    parser.add_argument("-K", required=True, help="Authentication token")
    parser.add_argument("-S", action="store_true", help="Print state of campus")
    parser.add_argument("-T", action="store_true", help="Calculate total time spent")
    parser.add_argument("-E", action="append", help="Employee name")
    parser.add_argument("-G", action="append", help="Guest name")
    parser.add_argument("-R", action="store_true", help="List rooms entered")
    parser.add_argument("-I", action="store_true", help="List common rooms occupied")
    parser.add_argument("log", help="Path to the log file")

    args = parser.parse_args(args)

    # Load encryption key
    key = load_key()
    if key is None:
        return  # Exit if key loading failed
    key = 'cjwLeVHhTx7PWUEGJVpYiPVRDUrPORnupX7TZED7w/Q=' # Dummy Key

    # Authenticate the token
    if not authenticate(args.log, args.K, key):
        print("Integrity violation")
        return  # Exit without an error code

    # Process -S: Print state of the campus
    if args.S:
        employees, guests, rooms = read_state(args.log, key)
        print_state(employees, guests, rooms)

    # Process -T: Calculate total time for employee or guest
    if args.T:
        if args.E:
            total_time = calculate_total_time(args.log, args.E[0], "employee", key)
        elif args.G:
            total_time = calculate_total_time(args.log, args.G[0], "guest", key)
        else:
            print("Error: Specify either -E for employee or -G for guest.")
            return  # Exit without an error code

        if total_time > 0:
            print(total_time)

    # Process -R: List rooms entered by employee or guest
    if args.R:
        if args.E:
            rooms_visited = list_rooms(args.log, args.E[0], "employee", key)
        elif args.G:
            rooms_visited = list_rooms(args.log, args.G[0], "guest", key)
        else:
            print("Error: Specify either -E for employee or -G for guest.")
            return  # Exit without an error code

        if rooms_visited:
            print(",".join(rooms_visited))

    # Process -I: List common rooms occupied by all specified employees and guests
    if args.I:
        names = []
        if args.E:
            names.extend(args.E)
        if args.G:
            names.extend(args.G)

        if not names:
            print("Error: Specify at least one -E for employee or -G for guest.")
            return  # Exit without an error code

        common_rooms = list_common_rooms(args.log, names, key)
        if common_rooms:
            print(",".join(common_rooms))

# Entry point for the script
if __name__ == "__main__":
    process_args()
