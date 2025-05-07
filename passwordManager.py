from config import *
import os
import json
import base64
import getpass
import ctypes
import stat
import uuid

import hashlib
import requests

from hashlib import sha256

import time
import pyperclip

import secrets
import string

from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from logging.handlers import RotatingFileHandler

import webbrowser
import pyautogui
import threading
import hashlib
import logging
import socket
import keyring


#-------------------------------------------------


# Variables for session timeout
last_action = time.time()


#--------------------------------------------------


# Basic configuration for logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

#----------------------------------

# Use to get a valid input from the user
def get_valid_input(prompt: str, valid_options: list = None, allow_empty: bool = False) -> str:
# Prompt str - The message to display to the user
# Valid_options list - A list of valid options for the user to choose from (optional)
# allow_empty bool - Whether to allow empty input (default: False)
# Returns the user's input as a string
    
    while True:
        user_input = input(prompt).strip() # Get user input and remove leading/trailing spaces
        if allow_empty and user_input == "": # Allow empty input if specified
            return user_input 
        if valid_options and user_input not in valid_options:  # Check if the input is in the list of valid options
            print(f"Invalid input. Please choose from: {', '.join(valid_options)}")
            continue
        return user_input
    

#----------------------------------


# Create a secure folder for storing the vault and salt files, encrypt it, and make it hidden
def create_secure_folder():

    if not os.path.exists(SECURE_FOLDER): # Check if the secure folder already exists
        os.makedirs(SECURE_FOLDER)

        os.chmod(SECURE_FOLDER, stat.S_IRWXU) # Restrict folder permissions to the owner (read, write, execute)

        # Make the folder hidden (Windows only) 
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02 # Windows attribute for hidden files/folders
            result = ctypes.windll.kernel32.SetFileAttributesW(SECURE_FOLDER, FILE_ATTRIBUTE_HIDDEN) # Set the folder attribute to hidden
            if result == 0:  # If the result is 0, the operation failed
                raise ctypes.WinError()
            logging.INFO(f"Secure folder is now hidden: {SECURE_FOLDER}")
        except Exception as e:
            print(f"Hiding folder failed: {e}")
            logging.INFO(f"Failed to hide folder: {e}")


#------------------------------------------------------------

# Create a backup folder for the log files
def create_backup_folder():

    if not os.path.exists(LOG_BACKUP_FOLDER):# Check if the backup folder already exists
        os.makedirs(LOG_BACKUP_FOLDER)


#------------------------------------------------


# Setup logging with a rotating file handler and an encrypted log handler
def setup_logging(fernet: Fernet):
# fernet - The Fernet object used for encryption/decryption

    logger = logging.getLogger()# Get the root logger
    logger.handlers.clear()  # Clear existing handlers

    rotating_handler = RotatingFileHandler( # 
        LOG_FILE, maxBytes=LOG_MAX_SIZE
    )

    rotating_handler.setLevel(logging.INFO) # Set the log level for the rotating handler
    rotating_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")) # Set the log format

    # Encrypted log handler
    encrypted_handler = EncryptedLogHandler(fernet) # Create an instance of the custom encrypted log handler
    encrypted_handler.setLevel(logging.INFO) # Set the log level for the encrypted handler

    # Add handlers to the logger
    logger.addHandler(rotating_handler) # Rotating log file
    logger.addHandler(encrypted_handler)  # Encrypted logs
    logger.setLevel(logging.INFO) # Set the log level for the logger


#-----------------------------------------------------------------------


# Create a custom log handler to encrypt log messages
class EncryptedLogHandler(logging.Handler):
# logging.Handler - Base class for all log handlers

    # Initialize the custom log handler
    def __init__(self, fernet): # fernet - The Fernet object used for encryption/decryption
        super().__init__() # Initialize the base class
        self.fernet = fernet # Store the Fernet object for encryption
        self.formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s") # Set the log format

    # Override the emit method to handle log messages
    def emit(self, record):
        try:
            
            msg = self.format(record) # Format the log message using the formatter

            encrypted = self.fernet.encrypt(msg.encode()) # Encrypt the log message using Fernet

            # Write the encrypted log message to the log file
            with open(LOG_FILE, "ab") as f:
                f.write(encrypted + b"\n")
        except Exception as e:
            print(f"Error writing encrypted log: {e}")
            logging.error(f"Error in EncryptedLogHandler: {e}")


#-------------------------------------------------------------------------


# Decrypt and display logs from the log file
def decrypt_logs(log_file: str, fernet: Fernet):
# log_file - The path to the log file
# fernet - The Fernet object used for decryption

    try:
        with open(log_file, "rb") as f:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = fernet.decrypt(line.strip()) # Decrypt the log entry
                    print(decrypted.decode()) # Print the decrypted log entry
                    
                    # Exception handling for specific cases
                except InvalidToken:
                    print("Warning: Skipping an invalid or corrupted log entry.")
                except Exception as e:
                    print(f"Error processing a log entry: {e}")
    # Exception handling for specific cases
    except FileNotFoundError:
        print(f"Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error decrypting logs: {e}")


    input("\nPress Enter to return to the menu...")


#----------------------------------------------------


# Create a backup of the log file
def backup_logs():
    try:

        create_backup_folder() # Ensure the backup folder exists
        
        if not os.path.exists(LOG_FILE):# Check if the log file exists
            print("No log file found to back up.")
            return

        # Generate a timestamped backup file name
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(LOG_BACKUP_FOLDER, f"password_manager_{timestamp}.log")

        # Copy the log file to the backup folder
        with open(LOG_FILE, "rb") as src, open(backup_file, "wb") as dst:
            dst.write(src.read())

        logging.info(f"Log file backed up to {backup_file}")

    except Exception as e:
        print(f"Error backing up logs: {e}")
        logging.error(f"Error backing up logs: {e}")

    # Delete old log backups (older than 30 days)
    for f in os.listdir(LOG_BACKUP_FOLDER):
        file_path = os.path.join(LOG_BACKUP_FOLDER, f)  # Prepend the folder path
        try:
            if os.stat(file_path).st_mtime < (time.time() - 30 * 86400):
                os.remove(file_path)
                logging.info(f"Deleted old backup: {file_path}")
        except FileNotFoundError:
            logging.warning(f"File not found during cleanup: {file_path}")
        except Exception as e:
            logging.error(f"Error deleting old backup {file_path}: {e}")


#-------------------------------------------------


# Log user information
def log_user_info():

    username = os.getlogin()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    logging.info(f"User: {username}, Hostname: {hostname}, IP: {ip_address}")


#--------------------------------------------------


# Export keys to a file
def export_keys(master_password: str, export_path: str):
# master_password - The master password used for encryption
# export_path - The path to the export file

    try:
        # Retrieve the encryption key and salt encryption key
        encryption_key = keyring.get_password(SERVICE_NAME, "encryption_key")
        salt_encryption_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")

        if not encryption_key or not salt_encryption_key: # Check if keys are found in keyring
            print("Keys not found in keyring.")
            return

        # Write the keys to the export file
        with open(export_path, "w") as f:
            f.write(f"Encryption Key: {encryption_key}\n")
            f.write(f"Salt Encryption Key: {salt_encryption_key}\n")

        print(f"Keys exported successfully to {export_path}")
        logging.info(f"Keys exported to {export_path}")

    except Exception as e:
        print(f"Error exporting keys: {e}")
        logging.error(f"Error exporting keys: {e}")


#-------------------------------------------------


# Check if the password has been compromised using HIBP API
def check_password_hibp(password: str) -> bool:
# password - The password to check

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper() # Hash the password using SHA1
    prefix, suffix = sha1_hash[:5], sha1_hash[5:] #Split the hash into prefix and suffix

    # Query the HIBP API with the first 5 characters of the hash
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print("Error querying HIBP API.")
            return False

        # Check if the suffix exists in the response
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                logging.warning(f"Password found in {count} breaches!")
                print(f"Password found in {count} breaches!")
                return True

        print("Password not found in any known breaches.")
        return False
    except requests.RequestException as e:
        logging.error(f"Error connecting to HIBP API: {e}")
        print(f"Error connecting to HIBP API: {e}")
        return False


#--------------------------------------------------


# Check if the password has been compromised using HIBP API for all passwords in the vault
def check_vault_passwords(vault: list):
# vault - The list of entries in the vault

    logging.info("Checking passwords in the vault...")
    if not vault:
        print("The vault is empty.")
        return
    clear_screen()
    show_title()
    print("\nCHECK PASSWORDS\n")

    print("\nChecking passwords in the vault...\n")

    # Loop through each entry in the vault and check the password
    for entry in vault:
        site = entry['site']
        password = entry['password']
        print(f"Checking password for site: {site}")
        if check_password_hibp(password):
            logging.warning(f"Password for {site} has been compromised!")
            print(f"WARNING: The password for {site} has been compromised! Change the password immidiately!.")
        else:
            print(f"The password for {site} is safe.")

    input("\nPress Enter to return to the menu...")


# Check for session timeout
def check_and_reset_timer():
  
    global last_action  # Use the global variable to track the last action time
    remaining_time = SESSION_TIMEOUT - (time.time() - last_action) # Calculate remaining time
    
    # Check if the session has expired
    if remaining_time <= 0:
        clear_screen()
        print("Session expired due to inactivity.")
        logging.info("Session expired due to inactivity.")
        exit(0)  # Exit the program if the session has expired
    last_action = time.time()  # Reset the timer

#--------------------------------------------------


# Derive PEPPER from the machine's unique identifier
def get_machine_pepper() -> str:

    machine_id = str(uuid.getnode()) + socket.gethostname()  # Combine hardware ID and hostname
    return sha256(machine_id.encode()).hexdigest()  # Hash the combined identifiers


#-----------------------------------------------------------

# Get the machine's unique identifier and derive PEPPER
PEPPER = get_machine_pepper()


#-----------------------------------------------------------


# Derive a key from the master password and salt
def derive_key(master_password: str, salt: bytes) -> bytes:
# master_password - The master password used for key derivation
    
    master_password += PEPPER # Combine the master password with PEPPER
    
    # Derive a key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_000_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode())) # Return the derived key in URL-safe base64 format


#--------------------------------------------------


# Secure the vault file by restricting permissions
def secure_file(file_path: str, grant_access=False):
# file_path - The path to the file to secure
# grant_access - Whether to grant access to the file (default: False)

    # Check if the file exists
    if os.path.exists(file_path):
        if grant_access:
            # Temporarily grant read/write permissions to the owner
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        else:
            # Remove all permissions
            os.chmod(file_path, 0)


#-------------------------------------------------


# Generate a random 
def generate_password(length: int = PASSWORD_LENGTH_DEFAULT,include_special_chars:bool = True) -> str:
# length - The length of the password to generate (default: 16)
# include_special_chars - Whether to include special characters (default: True)


    if length < 8:
        print(" Minimum password's length is 8 char.")
        return ""
    
    #Check for special characters
    mandatory_special_character = "@#!+=_-"
    characters = string.ascii_letters + string.digits
    if include_special_chars:
        characters += mandatory_special_character

    # Generate a random password
    password = ''.join(secrets.choice(characters) for _ in range(length)) # Generate a random password using the specified characters
    return password


#-------------------------------------------------


# Get the encryption key from the keyring or generate a new one
def get_encryption_key(master_password: str) -> bytes:
## master_password - The master password used for key derivation
    
    # Try to retrieve the key from keyring
    stored_key = keyring.get_password(SERVICE_NAME, "encryption_key")
    if stored_key:
        # Return the stored key
        return base64.urlsafe_b64decode(stored_key)

    # Generate a new key if not found
    new_key = Fernet.generate_key()

    # Store the new key in keyring
    keyring.set_password(SERVICE_NAME, "encryption_key", base64.urlsafe_b64encode(new_key).decode())

    return new_key


# ---------------------------------------------------


# Get the salt encryption key from the keyring or generate a new one
def get_salt_encryption_key(master_password: str, salt: bytes) -> bytes:
# master_password - The master password used for key derivation
# salt - The salt used for key derivation

    # Try to retrieve the key from keyring
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive((master_password + "SALT_ENCRYPTION").encode()))


#----------------------------------------------------------------------------


# Save the salt encryption key to the keyring
def save_salt_key_to_keyring(master_password: str, salt: bytes):
# master_password - The master password used for key derivation
# salt - The salt used for key derivation


    salt_key = get_salt_encryption_key(master_password, salt) # Get the salt encryption key
    keyring.set_password(SERVICE_NAME, "salt_encryption_key", salt_key.decode()) # Store the key in keyring


#------------------------------------------------------------------------------


# Ensure the secure folder exists before loading the encryption key
create_secure_folder()


#---------------------------------------------------------------------------------


# Load the encryption key from the keyring or generate a new one
def encrypt_salt_file(master_password: str):
# master_password - The master password used for key derivation

    # Check if the salt file exists, if not, create it
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    
    # Read the salt from the file
    with open(SALT_FILE, "rb") as f:
        plain_salt = f.read()
    
    # Encrypt the salt using the master password
    salt_key = get_salt_encryption_key(master_password, plain_salt) # Get the salt encryption key
    fernet = Fernet(salt_key) # Create a Fernet object for encryption
    encrypted_salt = fernet.encrypt(plain_salt) # Encrypt the salt
    
    # Write the encrypted salt back to the file
    with open(SALT_FILE, "wb") as f:
        f.write(encrypted_salt)
    
    # Save the salt encryption key to the keyring
    save_salt_key_to_keyring(master_password, plain_salt)


#-----------------------------------------------------------------------------------------


# Decrypt the salt file using the master password and the key from the keyring
def decrypt_salt_file(master_password: str) -> bytes:
# master_password - The master password used for key derivation


    # Check if the salt file exists
    with open(SALT_FILE, "rb") as f:
        encrypted_salt = f.read()
    
    # # Get the salt encryption key from the keyring
    salt_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")
    if not salt_key:
        raise ValueError("Salt encryption key not found in keyring!")
    
    # Decrypt the salt using the key from the keyring
    fernet = Fernet(salt_key.encode())
    return fernet.decrypt(encrypted_salt)


#-------------------------------------------------


# Hash the vault file using SHA256
def compute_file_hash(file_path: str) -> str:
# file_path - The path to the file to hash

    # Check if the file exists
    if not os.path.exists(file_path):
        return None 

    # Create a SHA256 hash object
    sha256_hash = hashlib.sha256()
    try:
        # Open the file in binary mode
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error computing hash for {file_path}: {e}")
        return None


#---------------------------------------------------


# initiallze the vault
def init_vault():

    # Check if the vault and salt files already exist
    if os.path.exists(SALT_FILE) and os.path.exists(VAULT_FILE):
        print("Vault already initialized.")
        return False  # Vault is already initialized

    ## Create the secure folder if it doesn't exist
    master_pwd = getpass.getpass("Set a master password: ")
    confirm_pwd = getpass.getpass("Confirm the master password: ")
    if master_pwd != confirm_pwd:
        print("Passwords don't match.")
        exit(1)

    # Generate a random salt and save it to the file
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    # Encrypt the salt file
    encrypt_salt_file(master_pwd)

    # Derive the vault key
    decrypted_salt = decrypt_salt_file(master_pwd)
    vault_key = derive_key(master_pwd, decrypted_salt)
    fernet = Fernet(vault_key)

    
    # Save the vault key to the keyring
    save_vault(fernet, [])


#----------------------------------------------


# Load the vault from the file
def load_vault(fernet: Fernet) -> list:
# fernet - The Fernet object used for decryption

    # Check if the vault file exists
    if not os.path.exists(VAULT_FILE):
        return []

    try:
        # Read the encrypted vault data from the file
        with open(VAULT_FILE, "rb") as f:
            data = f.read()

        # Decrypt the vault data
        decrypted = fernet.decrypt(data)
        return json.loads(decrypted)

    ## Exception handling for specific cases
    except InvalidToken:
        print("Master password not found. Decryption failed.")
        exit(1)  # Exit if the master password is incorrect
    except json.JSONDecodeError:
        print("Corrupted vault. Unable to parse JSON.")
        exit(1)  # Exit if the vault file is corrupted
    except FileNotFoundError:
        print("Vault file not found.")
        return []  # Return an empty list if the file doesn't exist
    except Exception as e:
        print(f"Unexpected error loading the vault: {e}")
        exit(1)


        
# Save the chyphered vault to the file
def save_vault(fernet: Fernet, vault: list):
# fernet - The Fernet object used for encryption
    
    secure_file(VAULT_FILE, grant_access=True)  # Temporarily grant permissions
    try:
        # Encrypt the vault data
        data = json.dumps(vault).encode()
        encrypted = fernet.encrypt(data)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

        secure_file(VAULT_FILE, grant_access=False)  # Revoke permissions

        # Compute and display the hash of the saved file
        file_hash = compute_file_hash(VAULT_FILE)
        if file_hash:
            logging.INFO(f"Vault saved successfully. File hash: {file_hash}")

    # Exception handling
    except FileNotFoundError:
        print("Vault file not found. Unable to save.")
        exit(1)
    except PermissionError:
        print("Permission denied. Unable to save the vault.")
        exit(1)
    except Exception as e:
        print(f"Unexpected error saving the vault: {e}")
        exit(1)


#-------------------------------------------------


# Add a new item
def add_entry(vault: list):
# vault - The list of entries in the vault

    while True:  # Loop until valid input is provided
        clear_screen()
        show_title()
        print("\nADD A NEW ACCOUNT\n")
        check_and_reset_timer()  # Enforce timeout globally

        try:
            # Get user input for site, username, URL, and password
            site = get_valid_input("Site (or leave blank to cancel): ", allow_empty=True)
            if not site:
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return 

            user = get_valid_input("Username (or leave blank to cancel): ", allow_empty=True)
            if not user:
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return  #

            url = get_valid_input("URL (or leave blank to cancel): ", allow_empty=True)
            if not url:
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return

            # Ask for password input method
            print("\n[1] Set manually a password\n[2] Generate a secure password\n\n[0] Cancel")
            choice = get_valid_input("> ", valid_options=["0", "1", "2"])

            if choice == "0":
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return
            elif choice == "1":
                pwd = getpass.getpass("Password (or leave blank to cancel): ").strip()
                if not pwd:
                    print("cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return
            elif choice == "2":
                length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                if not length:
                    print("cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return 
                
                length = int(length) if length.isdigit() else 24
                # Check if the user wants to include special characters
                include_special_chars = get_valid_input("Include special characters? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
                if not include_special_chars:
                    print("cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return 
                pwd = generate_password(length, include_special_chars == "y")
                print(f"Password generated: {pwd}")

            # Add the entry to the vault
            vault.append({"site": site, "username": user, "password": pwd, "url": url})
            print("Credentials entered correctly.")
            logging.info(f"Added new entry for site: {site}, url: {url}")
            break  # Exit the loop after successful entry

        # Exception handling for specific cases
        except ValueError:
            print("Invalid input. Please try again.")
            logging.error("ValueError occurred while adding an entry.")
        except Exception as e:
            print(f"Unexpected error adding an entry: {e}")
            logging.error(f"Unexpected error: {e}")

        input("\nPress Enter to return to the menu...")


#-------------------------------------------------


# Delete an entry
def delete_entry(vault: list):
# vault - The list of entries in the vault

    while True:  # Loop until valid input is provided
        check_and_reset_timer() 
        show_entries(vault, copy_enabled=False, justView_enabled=False) # Show entries without copy option
        if not vault:
            return

        try:
            
            # Get the index of the entry to delete
            idx = get_valid_input("ID to delete (or leave blank to cancel): ", allow_empty=True)
            if not idx:
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return  # Return to the menu
            idx = int(idx) - 1
            if 0 <= idx < len(vault):
                # Confirm deletion
                confirm = get_valid_input(f"Do you confirm the deletion of {vault[idx]['site']}? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
                if not confirm or confirm == "n":
                    print("cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return  # Return to the menu
                elif confirm == "y":
                    deleted_entry = vault[idx]
                    del vault[idx]
                    logging.info(f"Deleted entry for site: {deleted_entry['site']}, username: {deleted_entry['username']}")
                    print("Entry deleted.")
                    break  # Exit the loop after successful deletion
                else:
                    print("Invalid option. Please try again.")
            else:
                print("Invalid index. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


#-------------------------------------------------


# Edit an entry
def edit_entry(vault: list):
# vault - The list of entries in the vault

    while True:  # Loop until valid input is provided
        check_and_reset_timer()  # Enforce timeout globally

        show_entries(vault, copy_enabled=False, justView_enabled=False) # Show entries without copy option
        if not vault:
            return

        try:
            # Get the index of the entry to edit
            idx = get_valid_input("Enter the account index to edit (leave blank to cancel): ", allow_empty=True)
            if not idx:
                print("cancelled...")
                time.sleep(3)  # Add delay for cancellation
                return
            idx = int(idx) - 1

            if 0 <= idx < len(vault):
                entry = vault[idx]
                original_entry = entry.copy()  # Keep a copy of the original entry for logging
                print(f"Editing {entry['site']}")

                # Get new values for username, URL, and password
                new_user = get_valid_input(f"New username (leave blank to keep '{entry['username']}'): ", allow_empty=True)
                new_url = get_valid_input(f"New URL (leave blank to keep '{entry['url']}'): ", allow_empty=True)

                # Ask for password input method
                print("\n[1] Keep the current password\n[2] Manually enter a new password\n[3] Generate a new password\n[0] Cancel")
                choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

                new_pwd = None
                if choice == "0":
                    print("cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return  # Return to the menu
                elif choice == "2":
                    new_pwd = getpass.getpass("New password (or leave blank to cancel): ").strip()
                    if not new_pwd:
                        print("cancelled...")
                        time.sleep(3)  # Add delay for cancellation
                        return  # Return to the menu
                elif choice == "3":
                    length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                    if not length:
                        print("cancelled...")
                        time.sleep(3)  # Add delay for cancellation
                        return  # Return to the menu
                    length = int(length) if length.isdigit() else 24
                    new_pwd = generate_password(length)
                    print(f"Generated password: {new_pwd}")

                # Update the entry with new values
                if new_user:
                    entry['username'] = new_user
                if new_url:
                    entry['url'] = new_url
                if new_pwd:
                    entry['password'] = new_pwd

                # Log the changes
                changes = []
                if new_user and new_user != original_entry['username']:
                    changes.append(f"Username changed from '{original_entry['username']}' to '{new_user}'")
                if new_url and new_url != original_entry['url']:
                    changes.append(f"URL changed from '{original_entry['url']}' to '{new_url}'")
                if new_pwd:
                    changes.append("Password was modified (not logged for security)")

                logging.info(f"Edited entry for site: {entry['site']}. Changes: {', '.join(changes)}")
                print("Account updated.")
                break  # Exit the loop after successful edit
            else:
                print("Invalid index. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


#-------------------------------------------------


# Show all entries in the vault
def show_entries(vault: list, copy_enabled=True,justView_enabled=True):
# vault - The list of entries in the vault
# copy_enabled - Whether to enable the copy option (default: True)
# justView_enabled - Whether to enable the view option (default: True)

    check_and_reset_timer()
    clear_screen()

    # Check if the vault is empty
    if not vault:
        print("\nThe vault is empty.")
        input("\nPress Enter to return to the menu...")
        return
    
    # Print the entries in a formatted way
    show_title()    
    print("\nACCOUNT LIST\n")
    viewed_sites = []
    for i, entry in enumerate(vault, 1):
        print(f"{i}. {entry['site']} | {entry['username']} | {'*' * len(entry['password'])}")
        viewed_sites.append(entry['site'])
    
    logging.info(f"Viewed entries: {', '.join(viewed_sites)}")# Log the viewed entries


    print("\n")

    # Check if the user wants to copy a password
    if copy_enabled:
        try:
            # Get the index of the entry to copy
            copy = input("\nDo you want to copy a password? Enter the index or press Enter to skip: ").strip()
            if copy:
                idx = int(copy) - 1
                if 0 <= idx < len(vault):
                    pyperclip.copy(vault[idx]['password']) # Copy the password to the clipboard
                    logging.info(f"Copied password for site: {vault[idx]['site']}") # Log the copied password
                    print("Password copied to clipboard, it will be ereased in 30 seconds for security.")

                    # Start a timer to clear the clipboard after 30 seconds
                    def clear_clipboard():
                        time.sleep(30)
                        pyperclip.copy("")
                    threading.Thread(target=clear_clipboard, daemon=True).start()
                else:
                    print("Cancel")
                    time.sleep(3)
        except ValueError:
            print("Invalid input.")

    # Check if you need to wait
    if justView_enabled:
        input("\nPress Enter to return to the menu...")


#-------------------------------------------------


# Export the vault to a user-specified location
def export_vault():

    try:
        if not os.path.exists(VAULT_FILE):
            print("Vault file not found. Please ensure the vault is initialized.")
            return

        # Ask the user for the export path
        export_path = input("Enter the path to export the vault (e.g., backup_vault.enc): ").strip()
        with open(VAULT_FILE, "rb") as src, open(export_path, "wb") as dst:
            dst.write(src.read())

        print(f"Vault exported successfully to {export_path}")
        logging.info(f"Vault exported to {export_path}")
    except Exception as e:
        print(f"Error exporting vault: {e}")
        logging.error(f"Error exporting vault: {e}")

    input("\nPress Enter to return to the menu...")


#--------------------------------------------------


# Menu search logs to a file
def search_logs_menu(log_file: str, fernet: Fernet):
# log_file - The path to the log file
# fernet - The Fernet object used for decryption

    while True:  # Loop until valid input is provided
        try:
            clear_screen()
            show_title()
            print("\nSEARCH LOGS")
            print("[1] Filter by Date (e.g., 2025-05-07)")
            print("[2] Filter by Log Level (e.g., INFO, ERROR)")
            print("[3] Filter by Keyword")
            print("[4] Combine Filters (e.g., Date + Log Level)")
            print("\n[0] Cancel\n")
            filter_type = get_valid_input("Choose a filter option: ", valid_options=["0", "1", "2", "3", "4"])

            if filter_type == "0":
                print("Cancelled...")
                time.sleep(3)
                return  # Return to the menu

            # Get filter values based on the selected option
            date_filter = None
            level_filter = None
            keyword_filter = None

            if filter_type in {"1", "4"}:
                date_filter = get_valid_input("Enter the date (YYYY-MM-DD, or leave blank to cancel): ", allow_empty=True)
                if not date_filter:
                    print("Cancelled...")
                    time.sleep(3)  # Add delay for cancellation
                    return  # Return to the menu
            if filter_type in {"2", "4"}:
                level_filter = get_valid_input("Enter the log level (INFO, WARNING, ERROR, or leave blank to cancel): ", allow_empty=True).upper()
                if not level_filter:
                    print("cancelled...")
                    time.sleep(3)
                    return  # Return to the menu
            if filter_type in {"3", "4"}:
                keyword_filter = get_valid_input("Enter the keyword to search for (or leave blank to cancel): ", allow_empty=True)
                if not keyword_filter:
                    print("cancelled...")
                    time.sleep(3)
                    return  # Return to the menu

            clear_screen()
            show_title()
            print("\nFILTERED LOGS:\n")
            with open(log_file, "rb") as f:
                for line in f:
                    if not line.strip():  # Skip empty lines
                        continue
                    try:
                        decrypted = fernet.decrypt(line.strip()).decode()

                        # Apply filters
                        if date_filter and date_filter not in decrypted.split(" ")[0]:
                            continue
                        if level_filter and level_filter not in decrypted:
                            continue
                        if keyword_filter and keyword_filter.lower() not in decrypted.lower():
                            continue

                        # Print the matching log entry
                        print(decrypted)
                    except InvalidToken:
                        print("Warning: Skipping an invalid or corrupted log entry.")
                    except Exception as e:
                        print(f"Error processing a log entry: {e}")
        except Exception as e:
            print(f"Error searching logs: {e}")
        input("\nPress Enter to return to the menu...")


#----------------------------------------------------------------------------


# Decrypt and display logs from the log file
def export_logs(log_file: str, fernet: Fernet):
# log_file - The path to the log file
# fernet - The Fernet object used for decryption

    try:
        # Ask the user for the export path
        export_path = input("Enter the path to export the logs (e.g., logs_export.txt): ").strip()
        with open(log_file, "rb") as f, open(export_path, "w") as export_file:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = fernet.decrypt(line.strip()).decode()
                    export_file.write(decrypted + "\n")

                # Exception handling for specific cases
                except InvalidToken:
                    export_file.write("Warning: Skipping an invalid or corrupted log entry.\n")
                except Exception as e:
                    export_file.write(f"Error processing a log entry: {e}\n")
        print(f"Logs exported successfully to {export_path}")
    except Exception as e:
        print(f"Error exporting logs: {e}")


#--------------------------------------------------


# Menu for log options
def log_view_menu(log_file: str, fernet: Fernet):
# log_file - The path to the log file
# fernet - The Fernet object used for decryption

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nLOG VIEW MENU\n")
        print("[1] View all logs")
        print("[2] Search logs by filter")
        print("[3] Export logs to a file")
        print("\n[0] Return to the previous menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

        if choice == "1":
            # View all logs
            clear_screen()
            show_title()
            print("\nALL LOGS:\n")
            decrypt_logs(log_file, fernet)
        elif choice == "2":
            # Search logs by filter
            search_logs_menu(log_file, fernet)
        elif choice == "3":
            # Export logs to a file
            export_logs(log_file, fernet)
        elif choice == "0":
            break


#-------------------------------------------------


# Menu for advanced options
def advanced_options(vault: list, fernet: Fernet, log_fernet: Fernet):
# vault - The list of entries in the vault
# fernet - The Fernet object used for encryption
# log_fernet - The Fernet object used for logging

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nADVANCED OPTIONS\n")
        print("[1] Export keys")
        print("[2] View log menu")
        print("[3] Export crypted vault backup")
        print("\n[0] Return to the menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

        if choice == "1":
            export_path = get_valid_input("Enter the path to export the keys: ", allow_empty=False)
            export_keys(fernet, export_path)
        elif choice == "2":
            log_view_menu(LOG_FILE, log_fernet)
        elif choice == "3":
            export_vault()
        elif choice == "0":
            break


#--------------------------------------------------------------------


# Manage entries in the vault
def manage_entries(vault: list, fernet: Fernet):
# vault - The list of entries in the vault
# fernet - The Fernet object used for encryption

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nACCOUNT MANAGEMENT\n")
        print("[1] View all")
        print("[2] Copy a password")
        print("[3] Edit an account")
        print("[4] Delete an account")
        print("[5] Auto-login (vulnerable to keyloggers)")
        print("[6] Check passwords integrity")
        print("\n[0] Return to the menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3", "4", "5", "6"])

        if choice == "1":
            show_entries(vault, copy_enabled=False)
        elif choice == "2":
            show_entries(vault, copy_enabled=True)
        elif choice == "3":
            edit_entry(vault)
            save_vault(fernet, vault)
        elif choice == "4":
            delete_entry(vault)
            save_vault(fernet, vault)
        elif choice == "5":
            auto_login(vault)
        elif choice == "6":
            check_vault_passwords(vault)
        elif choice == "0":
            break


#-------------------------------------------------


# Clear the screen function
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


#-------------------------------------------------


# Show the title of the program
def show_title():
    print("""\n
╔────────────────────────────────────────────────────────────────────────╗
│ _____                             _      _____                         │
│|  _  |___ ___ ___ _ _ _ ___ ___ _| |    |     |___ ___ ___ ___ ___ ___ │
│|   __| .'|_ -|_ -| | | | . |  _| . |    | | | | .'|   | .'| . | -_|  _|│
│|__|  |__,|___|___|_____|___|_| |___|    |_|_|_|__,|_|_|__,|_  |___|_|  │
│                                                           |___|        │
╚────────────────────────────────────────────────────────────────────────╝\n
                                                  made by @nicola-frattini\n""")


#-------------------------------------------------


# Check if the session has timed out and reset the timer
def auto_login(vault: list):
# vault - The list of entries in the vault

    check_and_reset_timer()

    show_entries(vault, copy_enabled=False, justView_enabled=False) # Show entries without copy option
    if not vault:
        return

    try:
        # Get the index of the entry to auto-login
        idx = int(input("Enter the account index to auto-login (leave blank to cancel): ").strip()) - 1
        if 0 <= idx < len(vault):
            entry = vault[idx]
            logging.info(f"Auto-login initiated for site: {entry['site']}, URL: {entry['url']}") # Log the auto-login attempt
            print(f"Opening {entry['site']}...")
            webbrowser.open(entry['url'])  # Open the URL in the default browser

            # Wait for the browser to load
            time.sleep(3)

            # Simulate typing the username and password
            pyautogui.typewrite(entry['username'])
            pyautogui.press('tab')  # Move to the password field
            pyautogui.typewrite(entry['password'])
            pyautogui.press('enter')  # Submit the form
            print("Auto-login completed.")
        else:
            print("Invalid index.")
    except ValueError:
        print("Invalid input.")


#-------------------------------------------------


# Main function
def main():

    # Initialize global variables
    global last_action

    # Ensure the secure folder exists
    create_secure_folder()
    create_backup_folder()

    # Initialize the vault
    init_vault()

    # Ask for master password
    master_pwd = getpass.getpass("Enter the master password: ")

    # Decrypt the salt file
    try:
        decrypted_salt = decrypt_salt_file(master_pwd)
    except Exception as e:
        print(f"Error decrypting salt file: {e}")
        exit(1)

    # Derive vault key
    vault_key = derive_key(master_pwd, decrypted_salt)
    fernet = Fernet(vault_key)

    # Set up encrypted logging
    log_fernet = Fernet(derive_key(master_pwd + "LOGS", decrypted_salt))
    setup_logging(log_fernet)

    logging.info("Session started.")
    log_user_info()

    # Load the vault
    vault = load_vault(fernet)

    try:
        while True:
            check_and_reset_timer()

            clear_screen()
            show_title()

            print("\nMAIN MENU\n")
            print("[1] Add an account")
            print("[2] Manage accounts")
            print("[3] Advanced options")
            print("\n[0] Exit\n")
            choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

            if choice == "1":
                add_entry(vault)
                save_vault(fernet, vault)
            elif choice == "2":
                manage_entries(vault, fernet)
            elif choice == "3":
                advanced_options(vault, fernet, log_fernet)
            elif choice == "0":
                logging.info("User logged out.")
                break
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")
    finally:
        logging.info("Session ended.")
        backup_logs()  # Back up logs at the end of the session
        

if __name__ == "__main__": 
    main()