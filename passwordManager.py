#COSE DA FARE



import os
import json
import base64
import getpass
import ctypes
import stat
import uuid
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
import win32crypt
import threading
import subprocess
import sys
import hashlib
import logging
import socket
import keyring

# Configure logging
LOG_FILE = "password_manager.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


#----------------------------------


SECURE_FOLDER = "secure_vault"
VAULT_FILE = os.path.join(SECURE_FOLDER, "vault.enc")
SALT_FILE = os.path.join(SECURE_FOLDER, "salt.bin")
LOG_BACKUP_FOLDER = "log_backups"


SERVICE_NAME = "PasswordManager"  # Name of the service for keyring

# Create a secure folder for storing the vault and salt files, encrypt it, and make it hidden
def create_secure_folder():

    if not os.path.exists(SECURE_FOLDER):
        os.makedirs(SECURE_FOLDER)

        # Restrict folder permissions to the owner (read, write, execute)
        os.chmod(SECURE_FOLDER, stat.S_IRWXU)

        # Make the folder hidden (Windows only) 
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            result = ctypes.windll.kernel32.SetFileAttributesW(SECURE_FOLDER, FILE_ATTRIBUTE_HIDDEN)
            if result == 0:  # If the result is 0, the operation failed
                raise ctypes.WinError()
            print(f"Secure folder is now hidden: {SECURE_FOLDER}")
        except Exception as e:
            print(f"Hiding folder failed: {e}")


def create_backup_folder():
    """Ensure the log backup folder exists."""
    if not os.path.exists(LOG_BACKUP_FOLDER):
        os.makedirs(LOG_BACKUP_FOLDER)


#-----------------------------------


# Configure logging with rotation
LOG_FILE = "password_manager.log"
LOG_MAX_SIZE = 5 * 1024 * 1024  # 5 MB

def setup_logging(fernet: Fernet):
    logger = logging.getLogger()
    logger.handlers.clear()  # Clear existing handlers

    rotating_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_SIZE
    )

    rotating_handler.setLevel(logging.INFO)
    rotating_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    # Encrypted log handler
    encrypted_handler = EncryptedLogHandler(fernet)
    encrypted_handler.setLevel(logging.INFO)

    # Add handlers to the logger
    logger.addHandler(encrypted_handler)  # Encrypted logs
    logger.setLevel(logging.INFO)




class EncryptedLogHandler(logging.Handler):
    def __init__(self, fernet):
        super().__init__()
        self.fernet = fernet
        self.formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    def emit(self, record):
        try:

            # Create a formatter for the log message

            msg = self.format(record)

            # Encrypt the log message
            encrypted = self.fernet.encrypt(msg.encode())

            # Write the encrypted log message to the log file
            with open(LOG_FILE, "ab") as f:
                f.write(encrypted + b"\n")
        except Exception as e:
            print(f"Error writing encrypted log: {e}")
            logging.error(f"Error in EncryptedLogHandler: {e}")


            


def decrypt_logs(log_file: str, fernet: Fernet):
    try:
        with open(log_file, "rb") as f:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = fernet.decrypt(line.strip())
                    print(decrypted.decode()) # Print the decrypted log entry
                except InvalidToken:
                    print("Warning: Skipping an invalid or corrupted log entry.")
                except Exception as e:
                    print(f"Error processing a log entry: {e}")
                    
    except FileNotFoundError:
        print(f"Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error decrypting logs: {e}")

    input("\nPress Enter to return to the menu...")


#----------------------------------------------------

# Create a backup of the log file
def backup_logs():
    try:
        # Ensure the backup folder exists
        create_backup_folder()

        # Check if the log file exists
        if not os.path.exists(LOG_FILE):
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

    try:
        # Retrieve the encryption key and salt encryption key
        encryption_key = keyring.get_password(SERVICE_NAME, "encryption_key")
        salt_encryption_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")

        if not encryption_key or not salt_encryption_key:
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


def install_missing_packages():
    """Check and install missing packages."""
    required_packages = [
        "cryptography",
        "pyperclip",
        "pyautogui",
        "keyring"
    ]

    for package in required_packages:
        try:
            __import__(package)  # Try to import the package
        except ImportError:
            print(f"Package '{package}' is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])



#----------------------------------


# Variables for session timeout
last_action = time.time()
SESSION_TIMEOUT = 300 # 5 minuti (in secondi)

#--------------------------------------------------


# Check for session timeout
def check_and_reset_timer():
  
    global last_action
    remaining_time = SESSION_TIMEOUT - (time.time() - last_action)
    if remaining_time <= 30:  # Notify if less than 30 seconds remain
        print(f"Warning: Your session will expire in {int(remaining_time)} seconds.")
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

PEPPER = get_machine_pepper()

# Derive a key from the master password and salt
def derive_key(master_password: str, salt: bytes) -> bytes:
    master_password += PEPPER
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_000_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


#--------------------------------------------------

# Secure the vault file by restricting permissions
def secure_file(file_path: str, grant_access=False):
    # Grant access to the owner only
    if os.path.exists(file_path):
        if grant_access:
            # Temporarily grant read/write permissions to the owner
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        else:
            # Remove all permissions
            os.chmod(file_path, 0)


#-------------------------------------------------


# Generate a random 
def generate_password(length: int = 24) -> str:
    if length < 8:
        print(" Minimum password's length is 8 char.")
        return ""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

#-------------------------------------------------

def get_encryption_key(master_password: str) -> bytes:
    """Retrieve or generate the encryption key using keyring and the master password."""
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


def get_salt_encryption_key(master_password: str, salt: bytes) -> bytes:
    """Deriva una chiave specifica per cifrare salt.bin"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive((master_password + "SALT_ENCRYPTION").encode()))

def save_salt_key_to_keyring(master_password: str, salt: bytes):
    """Salva la chiave di cifratura del salt nel keyring."""
    salt_key = get_salt_encryption_key(master_password, salt)
    keyring.set_password(SERVICE_NAME, "salt_encryption_key", salt_key.decode())



# Ensure the secure folder exists before loading the encryption key
create_secure_folder()



def encrypt_salt_file(master_password: str):
    """Cifra salt.bin con doppio layer: Fernet + chiave derivata da master password."""
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    
    # Layer 1: Leggi il salt grezzo
    with open(SALT_FILE, "rb") as f:
        plain_salt = f.read()
    
    # Layer 2: Cifra con chiave derivata da master password
    salt_key = get_salt_encryption_key(master_password, plain_salt)
    fernet = Fernet(salt_key)
    encrypted_salt = fernet.encrypt(plain_salt)
    
    # Sovrascrivi il file con il salt cifrato
    with open(SALT_FILE, "wb") as f:
        f.write(encrypted_salt)
    
    # Salva la chiave nel keyring
    save_salt_key_to_keyring(master_password, plain_salt)


def decrypt_salt_file(master_password: str) -> bytes:
    """Decifra salt.bin usando la chiave dal keyring."""
    # Leggi il salt cifrato
    with open(SALT_FILE, "rb") as f:
        encrypted_salt = f.read()
    
    # Recupera la chiave dal keyring
    salt_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")
    if not salt_key:
        raise ValueError("Salt encryption key not found in keyring!")
    
    # Decifra
    fernet = Fernet(salt_key.encode())
    return fernet.decrypt(encrypted_salt)

#-------------------------------------------------

# Hash the vault file using SHA256
def compute_file_hash(file_path: str) -> str:
    """Compute the SHA256 hash of a file."""
    if not os.path.exists(file_path):
        return None  # Return None if the file doesn't exist

    sha256_hash = hashlib.sha256()
    try:
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

    
    # Salva il vault vuoto
    save_vault(fernet, [])
#----------------------------------------------

# Load the vault from the file
def load_vault(fernet: Fernet) -> list:
    """Load the vault from the file."""
    if not os.path.exists(VAULT_FILE):
        return []

    try:
        with open(VAULT_FILE, "rb") as f:
            data = f.read()

        # Decrypt the vault data
        decrypted = fernet.decrypt(data)
        return json.loads(decrypted)

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
    
    secure_file(VAULT_FILE, grant_access=True)  # Temporarily grant permissions
    try:
        data = json.dumps(vault).encode()
        encrypted = fernet.encrypt(data)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)
        secure_file(VAULT_FILE, grant_access=False)  # Revoke permissions

        # Compute and display the hash of the saved file
        file_hash = compute_file_hash(VAULT_FILE)
        if file_hash:
            print(f"Vault saved successfully. File hash: {file_hash}")

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
    clear_screen()
    show_title()
    print("\nADD A NEW ACCOUNT\n")
    check_and_reset_timer()  # Enforce timeout globally

    try:
        site = input("Site: ").strip()
        check_and_reset_timer()
        user = input("Username: ").strip()
        url = input("URL: ").strip()
        if not site or not user or not url:
            print("Site, Username, and URL can't be blank.")
            logging.warning("Attempted to add an entry with blank fields.")
            return

        print("\n[1] Set manually a password\n[2] Generate a secure password")
        choice = input("> ").strip()
        check_and_reset_timer()

        if choice == "1":
            pwd = getpass.getpass("Password: ").strip()
        elif choice == "2":
            length = input("Password length (default 24): ").strip()
            length = int(length) if length.isdigit() else 24
            pwd = generate_password(length)
            print(f"Password generated: {pwd}")
        else:
            print("Option not valid.")
            logging.warning("Invalid option selected while adding an entry.")
            return

        vault.append({"site": site, "username": user, "password": pwd, "url": url})
        print("Credentials entered correctly.")
        logging.info(f"Added new entry for site: {site}")
    except ValueError:
        print("Invalid input. Please try again.")
        logging.error("ValueError occurred while adding an entry.")
    except Exception as e:
        print(f"Unexpected error adding an entry: {e}")
        logging.error(f"Unexpected error: {e}")
    finally:
        input("\nPress Enter to return to the menu...")


#-------------------------------------------------


# Delete an entry
def delete_entry(vault: list):
    check_and_reset_timer()

    show_entries(vault, copy_enabled=False, justView_enabled=False)
    if not vault:
        return
    try:
        # Ask for the index of the entry to delete
        idx = int(input("ID to delete (leave blank to cancel): ").strip()) - 1
        if 0 <= idx < len(vault):
            check_and_reset_timer()
            # Confirm deletion
            confirm = input(f"Do you confirm the deletion of {vault[idx]['site']}? (y/n): ").lower()
            check_and_reset_timer()
            if confirm == "y":
                deleted_entry = vault[idx]
                del vault[idx]
                logging.info(f"Deleted entry for site: {deleted_entry['site']}, username: {deleted_entry['username']}")
                print("Entry deleted.")
            else:
                print("Cancelled.")
        else:
            print("Invalid index.")
    except ValueError:
        print("Invalid input.")


#-------------------------------------------------


# Edit an entry
def edit_entry(vault: list):
    check_and_reset_timer()  # Enforce timeout globally

    show_entries(vault, copy_enabled=False, justView_enabled=False)
    if not vault:
        return
    try:
        idx = int(input("Enter the account index to edit (leave blank to cancel): ").strip()) - 1
        check_and_reset_timer()

        # Check if the index is valid
        if 0 <= idx < len(vault):
            entry = vault[idx]
            original_entry = entry.copy()  # Keep a copy of the original entry for logging
            print(f"Editing {entry['site']}")

            # Ask for new values
            new_user = input(f"New username (leave blank to keep '{entry['username']}'): ").strip()
            new_url = input(f"New URL (leave blank to keep '{entry['url']}'): ").strip()
            check_and_reset_timer()

            # Ask for type of password change
            print("\n[1] Keep the current password\n[2] Manually enter a new password\n[3] Generate a new password")
            choice = input("> ").strip()
            check_and_reset_timer()

            new_pwd = None
            if choice == "2":
                new_pwd = getpass.getpass("New password: ").strip()
            elif choice == "3":
                length = input("Password length (default 24): ").strip()
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
        else:
            print("Invalid index.")
    except ValueError:
        print("Invalid input.")


#-------------------------------------------------


# Show all entries in the vault
def show_entries(vault: list, copy_enabled=True,justView_enabled=True):
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
            copy = input("\nDo you want to copy a password? Enter the index or press Enter to skip: ").strip()
            if copy:
                idx = int(copy) - 1
                if 0 <= idx < len(vault):
                    pyperclip.copy(vault[idx]['password'])
                    logging.info(f"Copied password for site: {vault[idx]['site']}") # Log the copied password
                    print("Password copied to clipboard, it will be ereased in 30 seconds for security.")

                    # Start a timer to clear the clipboard after 30 seconds
                    def clear_clipboard():
                        time.sleep(30)
                        pyperclip.copy("")
                    threading.Thread(target=clear_clipboard, daemon=True).start()
                else:
                    print("Invalid index.")
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
    try:
        
        clear_screen() 
        show_title()
        print("\nSEARCH LOGS")
        print("[1] Filter by Date (e.g., 2025-05-07)")
        print("[2] Filter by Log Level (e.g., INFO, ERROR)")
        print("[3] Filter by Keyword")
        print("[4] Combine Filters (e.g., Date + Log Level)")
        filter_type = input("Choose a filter option: ").strip()

        if filter_type not in {"1", "2", "3", "4"}:
            print("Invalid option. Returning to the menu.")
            return
        
        # Get filter values based on the selected option
        date_filter = None
        level_filter = None
        keyword_filter = None

        if filter_type in {"1", "4"}:
            date_filter = input("Enter the date (YYYY-MM-DD): ").strip()
        if filter_type in {"2", "4"}:
            level_filter = input("Enter the log level (INFO, WARNING, ERROR): ").strip().upper()
        if filter_type in {"3", "4"}:
            keyword_filter = input("Enter the keyword to search for: ").strip()


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


def export_logs(log_file: str, fernet: Fernet):
    try:
        export_path = input("Enter the path to export the logs (e.g., logs_export.txt): ").strip()
        with open(log_file, "rb") as f, open(export_path, "w") as export_file:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = fernet.decrypt(line.strip()).decode()
                    export_file.write(decrypted + "\n")
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
    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nLOG VIEW MENU")
        print("[1] View all logs")
        print("[2] Search logs by filter")
        print("[3] Export logs to a file")
        print("[4] Return to the previous menu")
        choice = input("> ").strip()

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
        elif choice == "4":
            # Return to the previous menu
            break
        else:
            print("Invalid option.")# Pause before returning to the menu


#-------------------------------------------------


def advanced_options(vault: list, fernet: Fernet, log_fernet: Fernet):
    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nADVANCED OPTIONS")
        print("[1] Export keys")
        print("[2] View log menu")
        print("[3] Export crypted vault backup")
        print("[4] Return to the menu")
        choice = input("> ").strip()

        if choice == "1":
            export_path = input("Enter the path to export the keys: ").strip()
            export_keys(fernet, export_path)
        elif choice == "2":
            log_view_menu(LOG_FILE, log_fernet) 
        elif choice == "3":
            export_vault()
        elif choice == "4":
            break
        else:
            print("Invalid option.")

# Manage entries in the vault
def manage_entries(vault: list, fernet: Fernet):
    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print("\nACCOUNT MANAGEMENT")
        print("[1] View all")
        print("[2] Copy a password")
        print("[3] Edit an account")
        print("[4] Delete an account")
        print("[5] Auto-login (vulnerable to keyloggers)")
        print("[6] Return to the menu")
        choice = input("> ").strip()

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
            break
        else:
            print("Invalid option.")


#-------------------------------------------------


# Clear the screen function
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


#-------------------------------------------------


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


def auto_login(vault: list):
    check_and_reset_timer()

    show_entries(vault, copy_enabled=False, justView_enabled=False)
    if not vault:
        return

    try:
        idx = int(input("Enter the account index to auto-login (leave blank to cancel): ").strip()) - 1
        if 0 <= idx < len(vault):
            entry = vault[idx]
            logging.info(f"Auto-login initiated for site: {entry['site']}, URL: {entry['url']}") # Log the auto-login attempt
            print(f"Opening {entry['site']}...")
            webbrowser.open(entry['url'])  # Open the URL in the default browser

            # Wait for the browser to load
            time.sleep(5)

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


#-------------------------------------------------


# Main function
def main():
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
            print("[1] Add an account")
            print("[2] Manage accounts")
            print("[3] Advanced options")
            print("[4] Exit\n")
            choice = input("> ").strip()

            if choice == "1":
                add_entry(vault)
                save_vault(fernet, vault)
            elif choice == "2":
                manage_entries(vault, fernet)
            elif choice == "3":
                advanced_options(vault, fernet,log_fernet)
            elif choice == "4":
                logging.info("User logged out.")
                break
            else:
                print("Invalid option.")
                logging.warning("Invalid option selected in the main menu.")
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")
    finally:
        logging.info("Session ended.")
        backup_logs()  # Back up logs at the end of the session
        

if __name__ == "__main__":
    install_missing_packages() 
    main()