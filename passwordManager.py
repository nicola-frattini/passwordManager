from typing import Optional
from config import *
import os
import json
import base64
import getpass
import ctypes
import stat
import uuid
import tqdm

import hashlib
import requests

from hashlib import sha256

import time
import pyperclip

import secrets
import string



from cryptography.hazmat.primitives import hashes
from logging.handlers import RotatingFileHandler

import webbrowser
import pyautogui
import threading
import hashlib
import logging
import socket
import keyring
from colorama import Fore, Back, Style, init

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend


import pyotp
import qrcode

import gc
 

import sqlite3



# Initialize colorama to automatically reset text color/style after each print
init(autoreset=True)



#-------------------------------------------------


# Variables for session timeout
last_action = time.time()


#--------------------------------------------------

def init_sqlite_vault():
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL,
            url TEXT
        )
    """)
    conn.commit()
    conn.close()


def load_vault_sqlite(key: bytes) -> list:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, site, username, password, url FROM vault")
        rows = cursor.fetchall()
        vault = []
        for row in rows:
            try:
                decrypted_pwd = aes_decrypt(row[3], key).decode()
            except Exception as e:
                decrypted_pwd = "<decryption error>"
                logging.error(f"Error decrypting password for {row[1]}: {e}")
            vault.append({
                "id": row[0],
                "site": row[1],
                "username": row[2],
                "password": decrypted_pwd,
                "url": row[4]
            })
        return vault
    except Exception as e:
        print(Fore.RED + f"Error loading vault: {e}")
        logging.error(f"Error loading vault: {e}")
        return []
    finally:
        conn.close()


def encrypt_db_file(key: bytes):
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    encrypted = aes_encrypt(data, key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


def decrypt_db_file(key: bytes):
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    data = aes_decrypt(encrypted, key)
    with open(VAULT_FILE, "wb") as f:
        f.write(data)



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
            print(Fore.RED + f"Invalid input. Please choose from: {', '.join(valid_options)}")
            continue
        return user_input
    


#-------------------------------------------------


# Encrypt data using AES-256 with the provided key
def aes_encrypt(data: bytes, key: bytes) -> bytes:
# data - The plaintext data to encrypt
# key - The 256-bit encryption key


    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to make it a multiple of the block size (16 bytes)
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the ciphertext
    return iv + ciphertext

# Decrypt data using AES-256 with the provided key
def aes_decrypt(data: bytes, key: bytes) -> bytes:
# data - The encrypted data to decrypt
# key - The 256-bit decryption key
    
    if len(data) < 16:
        raise ValueError("Invalid data length. Data must be at least 16 bytes long.")

    # Extract the IV (first 16 bytes) and ciphertext
    iv = data[:16]
    ciphertext = data[16:]

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext





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
            logging.info(f"Secure folder is now hidden: {SECURE_FOLDER}")
        except Exception as e:
            print(Fore.RED + f"Hiding folder failed: {e}")
            logging.info(f"Failed to hide folder: {e}")

    # Ensure the security subdirectory exists
    security_folder = os.path.join(SECURE_FOLDER, "security")
    if not os.path.exists(security_folder):
        os.makedirs(security_folder)


#------------------------------------------------------------

# Create a backup folder for the log files
def create_backup_folder():

    if not os.path.exists(LOG_BACKUP_FOLDER):# Check if the backup folder already exists
        os.makedirs(LOG_BACKUP_FOLDER)


#------------------------------------------------

create_backup_folder() # Create the backup folder for logs

# Basic configuration for logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)




# Setup logging with a rotating file handler and an encrypted log handler
def setup_logging(key: bytes):
# key - The encryption key used for the encrypted log handler

    logger = logging.getLogger()# Get the root logger
    logger.handlers.clear()  # Clear existing handlers

    # Encrypted log handler
    encrypted_handler = EncryptedLogHandler(key) # Create an instance of the custom encrypted log handler
    encrypted_handler.setLevel(logging.INFO) # Set the log level for the encrypted handler

    # Add handlers to the logger
    logger.addHandler(encrypted_handler)  # Encrypted logs
    logger.setLevel(logging.INFO) # Set the log level for the logger



#-----------------------------------------------------------------------


# Create a custom log handler to encrypt log messages
class EncryptedLogHandler(logging.Handler):
# logging.Handler - Base class for all log handlers

    # Initialize the custom log handler
    def __init__(self, key: bytes):
        super().__init__() # Initialize the base class
        self.key = key # Encryption key
        self.formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s") # Set the log format

    # Override the emit method to handle log messages
    def emit(self, record):
        try:
            
            msg = self.format(record) # Format the log message using the formatter

            encrypted = aes_encrypt(msg.encode(),self.key) # Encrypt the log message using AES encryption

            # Write the encrypted log message to the log file
            with open(LOG_FILE, "ab") as f:
                f.write(encrypted + b"\n")
        except Exception as e:
            print(Fore.RED + f"Error writing encrypted log: {e}")
            logging.error(f"Error in EncryptedLogHandler: {e}")


#-------------------------------------------------------------------------


# Decrypt and display logs from the log file
def decrypt_logs(log_file: str, key: bytes):
# log_file - The path to the log file
# key - The encryption key used for decryption

    try:
        with open(log_file, "rb") as f:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = aes_decrypt(line.strip(),key)  # Decrypt the bytes
                    decrypted_str = decrypted.decode()  # Decode the decrypted bytes to a string

                    # Parse the log level from the decrypted log entry
                    if " - INFO - " in decrypted_str:
                        color = Fore.GREEN
                    elif " - WARNING - " in decrypted_str:
                        color = Fore.YELLOW
                    elif " - ERROR - " in decrypted_str:
                        color = Fore.RED
                    elif " - CRITICAL - " in decrypted_str:
                        color = Fore.MAGENTA + Style.BRIGHT
                    else:
                        color = Fore.WHITE

                    # Print the log entry with the appropriate color
                    print(color + decrypted_str + Style.RESET_ALL)

                except Exception as e:
                    print(Fore.RED + f"Error processing a log entry: {e}")

# Exception handling for specific cases
    except FileNotFoundError:
        print(Fore.RED + f"Log file '{log_file}' not found.")
    except Exception as e:
        print(Fore.RED + f"Error decrypting logs: {e}")

    input(f"\nPress Enter to return to the menu...")


#----------------------------------------------------


# Create a backup of the log file
def backup_logs():
    try:

        create_backup_folder() # Ensure the backup folder exists
        
        if not os.path.exists(LOG_FILE):# Check if the log file exists
            print("No log file found to back up.")
            return

        # Generate the daily backup file
        timestamp = time.strftime("%Y-%m-%d")
        backup_file = os.path.join(LOG_BACKUP_FOLDER, f"password_manager_{timestamp}.log")

        # Copy the log file to the backup folder
        with open(LOG_FILE, "rb") as src, open(backup_file, "wb") as dst:
            dst.write(src.read())

        logging.info(f"Log file backed up to {backup_file}")

    except Exception as e:
        print(Fore.RED + f"Error backing up logs: {e}")
        logging.error(f"Error backing up logs: {e}")

    # Delete old log backups (older than 30 days)
    for f in os.listdir(LOG_BACKUP_FOLDER):
        file_path = os.path.join(LOG_BACKUP_FOLDER, f)  # Prepend the folder path
        try:
            if os.stat(file_path).st_mtime < (time.time() - BACKUP_RETENTION_DAYS * 86400):
                os.remove(file_path)
                logging.info(f"Deleted old backup: {file_path}")
        except FileNotFoundError:
            logging.error(f"File not found during cleanup: {file_path}")
        except Exception as e:
            logging.error(f"Error deleting old backup {file_path}: {e}")
#-------------------------------------------------


# Log user information
def log_user_info():

    try:
        with open(USERNAME_FILE, "r") as f:
            account = f.read().strip()  # Read the account name from the file
    except Exception as e:
        account = "Unknown"  # Default to "Unknown" if the file is not found

    username = os.getlogin()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    logging.info(f"Account: {account} User: {username}, Hostname: {hostname}, IP: {ip_address}")


#--------------------------------------------------

# Setup 2FA using TOTP
def setup_2fa(master_password: str, salt: bytes):

    secret_key= pyotp.random_base32()  # Generate a random base32 secret key

    # Load the username
    username = "User"
    try:
        with open(USERNAME_FILE, "r") as f:
            username = f.read().strip()
    except FileNotFoundError:
        logging.warning("Username file not found. Defaulting to 'User'.")


    # Generate a QR code for the TOTP secret key
    totp = pyotp.TOTP(secret_key)
    qr_code_url = totp.provisioning_uri(name="PasswordManager", issuer_name=f"{username}")  # Generate the provisioning URI for the QR code

    # Display the QR code
    print(Fore.MAGENTA + "\nScan the QR code with your authenticator app:\n")
    qr = qrcode.QRCode()
    qr.add_data(qr_code_url)
    qr.make(fit=True)

    # Print the QR code in ASCII format
    qr.print_ascii()

    print("\nOr manually enter this key in your authenticator app: " + f"{secret_key}")

    print(Fore.RED + "\n!! This is the only opportunity to get the code. If you don't do it now, it will be lost forever.")
    input("\nPress Enter to continue...")  # Wait for user input

    
    # Encrypt the secret key
    encryption_key = derive_key(master_password, salt)
    encrypted_secret_key = aes_encrypt(secret_key.encode(), encryption_key)

    # Save the encrypted secret key to the file
    with open(FILE_2FA, "wb") as f:
        f.write(encrypted_secret_key)
    
    print(Fore.GREEN + "\n2FA setup complete.")   


#--------------------------------------------------


# Verify the 2FA code
def verify_2fa_code(master_password: str, salt: bytes) -> bool:

    try:

         # Check if the 2FA secret file exists
 
        if not os.path.exists(FILE_2FA):
            print(Fore.RED + "2FA secret key file not found. Please set up 2FA first.")
            logging.error("2FA secret key file not found.")
            return False

        # Load the secret key from the file
        with open(FILE_2FA, "rb") as f:
            encrypted_secret_key = f.read().strip()

        # Decrypt the secret key
        decryption_key = derive_key(master_password, salt)
        secret_key = aes_decrypt(encrypted_secret_key, decryption_key).decode()


        # Prompt the user for the 2FA code
        totp = pyotp.TOTP(secret_key)
        for attempt in range(1, 4): # Allow 3 attempts
            user_code = get_valid_input("Enter the 2FA code: ", allow_empty=False)

            # Verify the 2FA code
            if totp.verify(user_code):
                print(Fore.GREEN + "2FA code verified successfully.")
                logging.info("2FA code verified successfully.")
                return True

            else:
                print(Fore.RED + "Invalid 2FA code. please try again.")
                logging.warning("Invalid 2FA code.")

        # If all attempts fail
        print(Fore.RED + "2FA verification failed. Please try again later.")
        logging.error("2FA verification failed after 3 attempts.")
        return False
        
    except FileNotFoundError:
        print(Fore.RED + "2FA secret key file not found. Please set up 2FA first.")
        logging.error("2FA secret key file not found.")
        return False
    except Exception as e:
        print(Fore.RED + f"Error verifying 2FA code: {e}")
        logging.error(f"Error verifying 2FA code: {e}")
        return False



#--------------------------------------------------


# Export all keys to a file
def export_keys(export_path: str, master_password: str,salt: bytes):
   
    try:
        
        steps = [
            "Decrypting the salt file...",
            "Deriving encryption keys...",
            "Retrieving stored keys...",
            "Writing keys to the export file..."
        ]

        # Initialize the progress bar
        progress_bar = tqdm.tqdm(steps, desc="Exporting Keys", ascii=True, ncols=75, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}")

        # Step 1: Decrypt the salt file
        progress_bar.set_description(steps[0])
        salt = decrypt_salt_file(master_password)
        progress_bar.update(1)

        # Step 2: Derive the encryption key, salt encryption key, and log key
        progress_bar.set_description(steps[1])
        encryption_key = get_encryption_key(master_password, salt)
        salt_encryption_key = get_salt_encryption_key(master_password, salt)
        log_key = derive_key(master_password + "LOGS", salt)
        progress_bar.update(1)

        # Step 3: Retrieve additional keys from the keyring
        progress_bar.set_description(steps[2])
        stored_encryption_key = keyring.get_password(SERVICE_NAME, "encryption_key")
        stored_salt_encryption_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")
        progress_bar.update(1)

        # Step 4: Write the keys to the export file
        progress_bar.set_description(steps[3])
        if not export_path:
            progress_bar.close()
            print(Fore.RED + "Export path cannot be empty.")
            return

        with open(export_path, "w") as f:
            os.chmod(export_path, stat.S_IRUSR | stat   .S_IWUSR)  # Restrict file permissions to the owner

            # Export derived keys
            f.write("=== Derived Keys ===\n")
            f.write(f"Encryption Key (Derived): {base64.urlsafe_b64encode(encryption_key).decode()}\n")
            f.write(f"Salt Encryption Key (Derived): {base64.urlsafe_b64encode(salt_encryption_key).decode()}\n")
            f.write(f"Log Key (Derived): {base64.urlsafe_b64encode(log_key).decode()}\n")

            # Export stored keys from the keyring
            f.write("\n=== Stored Keys ===\n")
            if stored_encryption_key:
                f.write(f"Encryption Key (Stored): {stored_encryption_key}\n")
            else:
                progress_bar.close()
                f.write("Encryption Key (Stored): Not Found\n")

            if stored_salt_encryption_key:
                f.write(f"Salt Encryption Key (Stored): {stored_salt_encryption_key}\n")
            else:
                progress_bar.close()
                f.write("Salt Encryption Key (Stored): Not Found\n")

        progress_bar.update(1)
        progress_bar.close()

        print(Fore.GREEN + f"Keys exported successfully to {export_path}")
        logging.info(f"Keys exported to {export_path}")

    except ValueError as ve:
        print(Fore.RED + f"Error: {ve}")
        logging.error(f"Error exporting keys: {ve}")
    except PermissionError:
        print(Fore.RED + "Permission denied. Unable to write to the specified path.")
        logging.error("Permission denied while exporting keys.")
    except FileNotFoundError:
        print(Fore.RED + "Invalid path. Please provide a valid file path.")
        logging.error("Invalid path provided for exporting keys.")
    except Exception as e:
        print(Fore.RED + f"Unexpected error exporting keys: {e}")
        logging.error(f"Unexpected error exporting keys: {e}")

    input("\nPress Enter to return to the menu...")


#-------------------------------------------------


# Check if the password has been compromised using HIBP API
def check_password_hibp(password: str) -> int:
# password - The password to check

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper() # Hash the password using SHA1
    prefix, suffix = sha1_hash[:5], sha1_hash[5:] #Split the hash into prefix and suffix

    # Query the HIBP API with the first 5 characters of the hash
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print("Fore.RED + Error querying HIBP API.")
            return 0

        # Check if the suffix exists in the response
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                logging.warning(f"Password found in {count} breaches!")
                return {count}

        return 0
    except requests.RequestException as e:
        logging.error(f"Error connecting to HIBP API: {e}")
        print(Fore.RED + f"Error connecting to HIBP API: {e}")
        return 0


#--------------------------------------------------


# Check if the password has been compromised using HIBP API for all passwords in the vault
def check_vault_passwords(vault: list,vault_key: bytes):
# vault - The list of entries in the vault
# vault_key - The encryption key used to encrypt the vault

    logging.info("Checking passwords in the vault...")
    if not vault:
        print(Fore.RED + "The vault is empty.")
        return
    
    clear_screen()
    show_title()
    print(Fore.MAGENTA +  Style.BRIGHT + "\nCHECK PASSWORDS\n")
    print("\nChecking passwords in the vault...\n")

    # Initialize a list to store results
    results = []

    # Loop through each entry in the vault and check the password
    with tqdm.tqdm(vault, desc="Checking passwords", ascii=True, ncols=75, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}") as progress_bar:
        for entry in progress_bar:
            password = entry['password']
            if check_password_hibp(password) != 0:
                try:
                    site = aes_decrypt(entry['site'], vault_key).decode()
                except Exception:
                    site = "<decryption error>"
                results.append((site, Fore.RED + f"WARNING: The password for {site} has been compromised! Change it immediately."))
                logging.warning(f"Password for {site} has been compromised!")
        
    progress_bar.close()

    print(Fore.GREEN + "\nPassword check completed.\n")
    if results:
        for site, message in results:
            print(message)
    else:
        print(Fore.GREEN + "No compromised passwords found in the vault.")

    input("\nPress Enter to return to the menu...")


# Check for session timeout
def check_and_reset_timer():
  
    global last_action  # Use the global variable to track the last action time
    remaining_time = SESSION_TIMEOUT - (time.time() - last_action) # Calculate remaining time
    
    # Check if the session has expired
    if remaining_time <= 0:
        clear_screen()
        print(Fore.RED + "Session expired due to inactivity.")
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
# salt - The salt used for key derivation

    
    master_password += PEPPER # Combine the master password with PEPPER
    
    # Derive a key using Argon2
    derived_key = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,  # Number of iterations
        memory_cost=64 * 1024,  # Memory usage in kibibytes (64 MB)
        parallelism=2,  # Number of parallel threads
        hash_len=32,  # Length of the derived key
        type=Type.ID  # Argon2id 
    )
    return (derived_key)  # Return the derived key 


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
def get_encryption_key(master_password: str,salt: bytes) -> bytes:
## master_password - The master password used for key derivation
    
    # Try to retrieve the key from keyring
    stored_key = keyring.get_password(SERVICE_NAME, "encryption_key")
    if stored_key:
        # Return the stored key
        return base64.urlsafe_b64decode(stored_key)

    # Generate a new key if not found
    new_key =derive_key(master_password, salt)

    # Store the new key in keyring
    keyring.set_password(SERVICE_NAME, "encryption_key", base64.urlsafe_b64encode(new_key).decode())

    return new_key


# ---------------------------------------------------


# Get the salt encryption key from the keyring or generate a new one
def get_salt_encryption_key(master_password: str, salt: bytes) -> bytes:
# master_password - The master password used for key derivation
# salt - The salt used for key derivation

    # Try to retrieve the key from keyring
    stored_key = keyring.get_password(SERVICE_NAME, "salt_encryption_key")
    if stored_key:
        # Decode the stored key from Base64 and return it
        return base64.urlsafe_b64decode(stored_key)

    # Generate a new key if not found
    derived_key = derive_key(master_password, salt) # Derive the key using the master password and salt

    encoded_key = base64.urlsafe_b64encode(derived_key).decode() # Encode the key to a string
    keyring.set_password(SERVICE_NAME, "salt_encryption_key", encoded_key) # Store the key in keyring
    
    return (derived_key)


#----------------------------------------------------------------------------


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

    # Retrieve the salt encryption key from the keyring
    salt_key = get_salt_encryption_key(master_password, plain_salt) # Get the salt encryption key

    # Encrypt the salt
    encrypted_salt = aes_encrypt(plain_salt, salt_key) # Encrypt the salt using the key

    # Write the encrypted salt back to the file
    with open(SALT_FILE, "wb") as f:
        f.write(encrypted_salt)

#-----------------------------------------------------------------------------------------


# Decrypt the salt file using the master password and the key from the keyring
def decrypt_salt_file(master_password: str) -> bytes:
# master_password - The master password used for key derivation


    # Check if the salt file exists
    with open(SALT_FILE, "rb") as f:
        encrypted_salt = f.read()
    
    # # Get the salt encryption key from the keyring
    salt_key = get_salt_encryption_key(master_password, encrypted_salt) # Get the salt encryption key


    # Decrypt the salt file
    return aes_decrypt(encrypted_salt, salt_key) 

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
        print(Fore.RED + f"Error computing hash for {file_path}: {e}")
        return None


#---------------------------------------------------


# initiallze the vault
def init_vault():

    # Check if the vault and salt files already exist
    if os.path.exists(SALT_FILE)  and os.path.exists(FILE_2FA) and os.path.exists(VAULT_FILE):
        return False  # Salt Vault and 2FA already initialized

    
    clear_screen() 
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT +"\nCREATING PASSWORD MANAGER \n\n")

    # prompt for the user's username
    username = get_valid_input("Enter your username: ", allow_empty=False)
    with open(USERNAME_FILE, "w") as f:
        f.write(username)
    
    # Prompt the user for a master password
    master_pwd = getpass.getpass("\nSet a master password: ")
    confirm_pwd = getpass.getpass("\nConfirm the master password: ")
    if master_pwd != confirm_pwd:
        print(Fore.RED + "Passwords don't match.")
        exit(1)


    # Generate a random salt and save it to the file
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
        logging.info("Salt file created.")

    # Encrypt the salt file
    encrypt_salt_file(master_pwd)


    # Derive the vault key
    decrypted_salt = decrypt_salt_file(master_pwd)
    vault_key = derive_key(master_pwd, decrypted_salt)
    
    init_sqlite_vault()

    encrypt_db_file(vault_key)  # Encrypt the vault file

    setup_2fa(master_pwd, decrypted_salt)  # Setup 2FA



#-------------------------------------------------


# Add a new item
def add_entry(vault_key: bytes):
# vault_key - The encryption key used to encrypt the vault

    while True:
        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT +"\nADD A NEW ACCOUNT\n")
        check_and_reset_timer()

        try:
            site = get_valid_input("Site (or leave blank to cancel): ", allow_empty=True)
            if not site:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            user = get_valid_input("Username (or leave blank to cancel): ", allow_empty=True)
            if not user:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            url = get_valid_input("URL (or leave blank to cancel): ", allow_empty=True)
            if not url:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            print("\n[1] Set manually a password\n[2] Generate a secure password\n\n[0] Cancel")
            choice = get_valid_input("> ", valid_options=["0", "1", "2"])

            if choice == "0":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            elif choice == "1":
                pwd = getpass.getpass("Password (or leave blank to cancel): ").strip()
                if not pwd:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
            elif choice == "2":
                length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                if not length:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
                length = int(length) if length.isdigit() else 24
                include_special_chars = get_valid_input("Include special characters? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
                if not include_special_chars:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
                pwd = generate_password(length, include_special_chars == "y")
                print(Fore.GREEN + f"Password generated: {pwd}")

            # Encrypt all fields before storing
            conn = sqlite3.connect(VAULT_FILE)
            cursor = conn.cursor()
            encrypted_site = aes_encrypt(site.encode(), vault_key)
            encrypted_user = aes_encrypt(user.encode(), vault_key)
            encrypted_pwd = aes_encrypt(pwd.encode(), vault_key)
            encrypted_url = aes_encrypt(url.encode(), vault_key)
            cursor.execute(
                "INSERT INTO vault (site, username, password, url) VALUES (?, ?, ?, ?)",
                (encrypted_site, encrypted_user, encrypted_pwd, encrypted_url)
            )
            conn.commit()
            conn.close()

            print(Fore.GREEN + "Credentials entered correctly.")
            logging.info(Fore.GREEN + f"Added new entry for site: {site}, url: {url}")
            break

        except ValueError:
            print(Fore.RED + "Invalid input. Please try again.")
            logging.error("ValueError occurred while adding an entry.")
        except Exception as e:
            print(Fore.RED + f"Unexpected error adding an entry: {e}")
            logging.error(f"Unexpected error: {e}")

    input("\nPress Enter to return to the menu...")

#-------------------------------------------------


# Delete an entry
def delete_entry(vault_key: bytes):
# vault_key - The encryption key used to encrypt the vault

    
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        conn.close()
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(vault_key, copy_enabled=False, justView_enabled=False)

    while True:
        try:
            idx = get_valid_input("ID to delete (or leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            idx = int(idx)
            cursor.execute("SELECT id, site FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()
            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again
            confirm = get_valid_input(Fore.RED + f"Do you confirm the deletion of {entry[1]}? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
            if not confirm or confirm == "n":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                conn.close()
                return
            elif confirm == "y":
                cursor.execute("DELETE FROM vault WHERE id=?", (idx,))
                conn.commit()
                print(Fore.GREEN + "Entry deleted.")
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a valid number.")
        finally:
            conn.close()


#-------------------------------------------------


# Edit an entry
def edit_entry(vault_key: bytes):
# vault_key - The encryption key used to encrypt the vault

    # Check if the vault is empty
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        conn.close()
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(vault_key, copy_enabled=False, justView_enabled=False)

    try:
        while True:
            idx = get_valid_input("Enter the account ID to edit (leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                break
            try:
                idx = int(idx)
            except ValueError:
                print("Invalid input. Please enter a valid number.")
                continue
            cursor.execute("SELECT id, site, username, password, url FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()
            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again

            try:
                decrypted_site = aes_decrypt(entry[1], vault_key).decode()
                decrypted_user = aes_decrypt(entry[2], vault_key).decode()
                decrypted_pwd = aes_decrypt(entry[3], vault_key).decode()
                decrypted_url = aes_decrypt(entry[4], vault_key).decode()
            except Exception:
                print(Fore.RED + "Could not decrypt one or more fields for this entry.")
                continue

            print(f"Editing {decrypted_site}")
            new_user = get_valid_input(f"New username (leave blank to keep '{decrypted_user}'): ", allow_empty=True)
            new_url = get_valid_input(f"New URL (leave blank to keep '{decrypted_url}'): ", allow_empty=True)
            print("\n[1] Keep the current password\n[2] Manually enter a new password\n[3] Generate a new password\n[0] Cancel")
            choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

            new_pwd = None
            if choice == "0":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                break
            elif choice == "2":
                new_pwd = getpass.getpass("New password (or leave blank to cancel): ").strip()
                if not new_pwd:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    break
            elif choice == "3":
                length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                if not length:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    break
                length = int(length) if length.isdigit() else 24
                new_pwd = generate_password(length)
                print(f"Generated password: {new_pwd}")

            if new_user:
                encrypted_user = aes_encrypt(new_user.encode(), vault_key)
                cursor.execute("UPDATE vault SET username=? WHERE id=?", (encrypted_user, idx))
            if new_url:
                encrypted_url = aes_encrypt(new_url.encode(), vault_key)
                cursor.execute("UPDATE vault SET url=? WHERE id=?", (encrypted_url, idx))
            if new_pwd:
                encrypted_pwd = aes_encrypt(new_pwd.encode(), vault_key)
                cursor.execute("UPDATE vault SET password=? WHERE id=?", (encrypted_pwd, idx))
            conn.commit()
            print(Fore.GREEN + "Account updated.")
            break  # Exit after successful edit
    finally:
        conn.close()


#-------------------------------------------------


# Show all entries in the vault
def show_entries(vault_key: bytes, copy_enabled=True, justView_enabled=True):
    check_and_reset_timer()
    clear_screen()

    # Load the vault from the file

    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()
    conn.close()

    # Check if the vault is empty
    if not rows:
        print(Fore.RED + "\nThe vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return
    
    # Print the entries in a formatted way
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT + "\nACCOUNT LIST\n")
    print(Fore.MAGENTA + "{:<5} {:<20} {:<20} {:<20}".format("ID", "Site", "Username", "Password"))
    print(Fore.MAGENTA + "-" * 75)

    decrypted_rows = []
    for row in rows:
        try:
            decrypted_site = aes_decrypt(row[1], vault_key).decode()
            decrypted_user = aes_decrypt(row[2], vault_key).decode()
            decrypted_pwd = aes_decrypt(row[3], vault_key).decode()
            decrypted_url = aes_decrypt(row[4], vault_key).decode()
        except Exception:
            decrypted_site = "<decryption error>"
            decrypted_user = "<decryption error>"
            decrypted_pwd = "<decryption error>"
            decrypted_url = "<decryption error>"
        decrypted_rows.append((row[0], decrypted_site, decrypted_user, decrypted_pwd, decrypted_url))
        print(Fore.WHITE + "{:<5} {:<20} {:<20} {:<20}".format(row[0], decrypted_site, decrypted_user, '*' * len(decrypted_pwd)))

    logging.info(f"Viewed entries")
    print("\n")

    if copy_enabled:
        while True:
            try:
                copy = input("\nDo you want to copy a password? Enter the ID or press Enter to skip: ").strip()
                if not copy:
                    # If user presses Enter, return to the previous menu
                    return
                idx = int(copy)
                for entry in decrypted_rows:
                    if entry[0] == idx:
                        pyperclip.copy(entry[3])
                        logging.info(Fore.GREEN + f"Copied password for site: {entry[1]}")
                        print(Fore.GREEN + "Password copied to clipboard, it will be erased in 30 seconds for security.")
                        def clear_clipboard():
                            time.sleep(30)
                            pyperclip.copy("")
                        threading.Thread(target=clear_clipboard, daemon=True).start()
                        input("\nPress Enter to return to the menu...")
                        return  # Success, exit the loop and function
                print(Fore.RED + "Invalid ID. Please try again.")
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a valid number or press Enter to cancel.")

    if justView_enabled:
        input("\nPress Enter to return to the menu...")


#-------------------------------------------------


# Export the vault to a user-specified location
def export_vault():
    try:
        if not os.path.exists(VAULT_FILE):
            print(Fore.RED + "Vault file not found. Please ensure the vault is initialized.")
            return

        # Ask the user for the export path (default to VAULT_FILE + ".backup")
        default_export_path = VAULT_FILE + ".backup"
        export_path = input(f"Enter the path to export the vault (default: {default_export_path}): ").strip()
        if not export_path:
            export_path = default_export_path

        with open(VAULT_FILE, "rb") as src, open(export_path, "wb") as dst:
            dst.write(src.read())

        print(Fore.GREEN + f"Vault exported successfully to {export_path}")
        logging.info(f"Vault exported to {export_path}")
    except Exception as e:
        print(Fore.RED + f"Error exporting vault: {e}")
        logging.error(f"Error exporting vault: {e}")

    input("\nPress Enter to return to the menu...")


#--------------------------------------------------


# Menu search logs to a file
def search_logs_menu(log_file: str, key: bytes):
# log_file - The path to the log file
# key - The encryption key used for decryption

    while True:  # Loop until valid input is provided
        try:
            clear_screen()
            show_title()
            print(Fore.MAGENTA  + Style.BRIGHT + "\nSEARCH LOGS")
            print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE +  " Filter by Date (e.g., 2025-05-07)")
            print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE +  " Filter by Log Level (e.g., INFO, ERROR)")
            print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE +  " Filter by Keyword")
            print(Fore.LIGHTMAGENTA_EX + "[4]" + Fore.WHITE +  " Combine Filters (e.g., Date + Log Level)")
            print(Fore.RED + "\n[0] Back to menu\n")
            filter_type = get_valid_input("> ", valid_options=["0", "1", "2", "3", "4"])

            if filter_type == "0":
                print("Back to menu")
                time.sleep(1)
                return  # Return to the menu

            # Get filter values based on the selected option
            date_filter = None
            level_filter = None
            keyword_filter = None

            if filter_type in {"1", "4"}:
                date_filter = get_valid_input("Enter the date (YYYY-MM-DD, or leave blank to cancel): ", allow_empty=True)
                if not date_filter:
                    print(Fore.RED + "Cancelled...")
                    time.sleep(2)  # Add delay for cancellation
                    return  # Return to the menu
            if filter_type in {"2", "4"}:
                level_filter = get_valid_input("Enter the log level (INFO, WARNING, ERROR, or leave blank to cancel): ", allow_empty=True).upper()
                if not level_filter:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return  # Return to the menu
            if filter_type in {"3", "4"}:
                keyword_filter = get_valid_input("Enter the keyword to search for (or leave blank to cancel): ", allow_empty=True)
                if not keyword_filter:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return  # Return to the menu

            clear_screen()
            show_title()
            print(Fore.CYAN + Style.BRIGHT + "\nFILTERED LOGS:\n")
            with open(log_file, "rb") as f:
                for line in f:
                    if not line.strip():  # Skip empty lines
                        continue
                    try:
                        decrypted = aes_decrypt(line.strip(),key).decode()

                        # Apply filters
                        if date_filter and date_filter not in decrypted.split(" ")[0]:
                            continue
                        if level_filter and level_filter not in decrypted:
                            continue
                        if keyword_filter and keyword_filter.lower() not in decrypted.lower():
                            continue

                        # Print the matching log entry
                        print(decrypted)
 
                    except Exception as e:
                        print(Fore.RED + f"Error processing a log entry: {e}")
 
        # Exception handling for specific cases
        except Exception as NoneTypeError:
            print(Fore.RED + "No log has been found.")
        except Exception as e:
            print(Fore.RED + f"Error searching logs: {e}")
        input(Fore.RED + "\nPress Enter to return to the menu...")


#----------------------------------------------------------------------------


# Decrypt and display logs from the log file
def export_logs(log_file: str, key: bytes):
# log_file - The path to the log file
# key - The encryption key used for decryption

    try:
        # Ask the user for the export path
        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT + "\nEXPORT LOGS\n")
        export_path = input("Enter the path to export the logs (e.g., logs_export.txt): ").strip()
        with open(log_file, "rb") as f, open(export_path, "w") as export_file:
            for line in f:
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    decrypted = aes_decrypt(line.strip(),key).decode()
                    export_file.write(decrypted + "\n")

                except Exception as e:
                    export_file.write(f"Error processing a log entry: {e}\n")

        print(Fore.GREEN + f"Logs exported successfully to {export_path}")

    except Exception as e:
        print(Fore.RED + f"Error exporting logs: {e}")
        logging.error(f"Error exporting logs: {e}")

    input("\nPress Enter to return to the menu...")

#--------------------------------------------------


# Menu for log options
def log_view_menu(log_file: str, key: bytes):
# log_file - The path to the log file
# key - The encryption key used for decryption

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT + "\nLOG VIEW MENU\n")
        print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE +  " View all logs")
        print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE +  " Search logs by filter")
        print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE +  " Export decrypted logs to a file")
        print(Fore.RED + "\n[0] Return to the previous menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

        if choice == "1":
            # View all logs
            clear_screen()
            show_title()
            print("\nALL LOGS:\n")
            decrypt_logs(log_file, key)
        elif choice == "2":
            # Search logs by filter
            search_logs_menu(log_file, key)
        elif choice == "3":
            # Export logs to a file
            clear_screen()
            show_title()
            export_logs(log_file, key)
        elif choice == "0":
            break


#-------------------------------------------------


# Menu for advanced options
def advanced_options (log_key: bytes, master_pwd: str,salt: bytes):
# log_key - The encryption key used for logging
# master_pwd - The master password used for key derivation
# salt - The salt used for key derivation

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT + "\nADVANCED OPTIONS\n")
        print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE +  " Export keys")
        print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE +  " View log menu")
        print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE +  " Export crypted vault backup")
        print(Fore.RED + "\n[0] Return to the menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

        if choice == "1":
            export_keys(input("Enter the path to export the keys (e.g., backup_keys.txt): ").strip(),master_pwd,salt)
        elif choice == "2":
            log_view_menu(LOG_FILE, log_key)
        elif choice == "3":
            export_vault()
        elif choice == "0":
            break


#--------------------------------------------------------------------


# Manage entries in the vault
def manage_entries(vault_key: bytes):
# vault_key - The encryption key used to encrypt the vault

    while True:
        check_and_reset_timer()  # Enforce timeout globally

        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT + "\nACCOUNT MANAGEMENT\n")
        print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE +  " View all")
        print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE +  " Copy a password")
        print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE +  " Edit an account")
        print(Fore.LIGHTMAGENTA_EX + "[4]" + Fore.WHITE +  " Delete an account")
        print(Fore.LIGHTMAGENTA_EX + "[5]" + Fore.WHITE +  " Auto-login (vulnerable to keyloggers)")
        print(Fore.LIGHTMAGENTA_EX + "[6]" + Fore.WHITE +  " Check passwords integrity")
        print(Fore.RED + "\n[0] Return to the menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3", "4", "5", "6"])

        if choice == "1":
            show_entries(vault_key, copy_enabled=False)
        elif choice == "2":
            show_entries(vault_key, copy_enabled=True, justView_enabled=False)
        elif choice == "3":
            edit_entry(vault_key)
        elif choice == "4":
            delete_entry(vault_key)
        elif choice == "5":
            auto_login(vault_key)
        elif choice == "6":
            check_vault_passwords(load_vault_sqlite(vault_key),vault_key)
        elif choice == "0":
            break


#-------------------------------------------------


# Clear the screen function
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


#-------------------------------------------------


# Show the title of the program
def show_title():
    print(Fore.MAGENTA +  Style.BRIGHT + """\n
╔────────────────────────────────────────────────────────────────────────╗
│ _____                             _      _____                         │
│|  _  |___ ___ ___ _ _ _ ___ ___ _| |    |     |___ ___ ___ ___ ___ ___ │
│|   __| .'|_ -|_ -| | | | . |  _| . |    | | | | .'|   | .'| . | -_|  _|│
│|__|  |__,|___|___|_____|___|_| |___|    |_|_|_|__,|_|_|__,|_  |___|_|  │
│                                                           |___|        │
╚────────────────────────────────────────────────────────────────────────╝\n
""" + Style.RESET_ALL)
    
    print(Fore.MAGENTA + "                                                 made by @nicola-frattini\n")


#-------------------------------------------------


# Check if the session has timed out and reset the timer
def auto_login(vault_key: bytes):
    check_and_reset_timer()

    # Load and show entries
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(vault_key, copy_enabled=False, justView_enabled=False)  # Show entries without copy option

    while True:
        try:
            idx = get_valid_input("Enter the account ID to auto-login (leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            idx = int(idx)
            # Fetch the entry from the database by ID
            conn = sqlite3.connect(VAULT_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT site, username, password, url FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()
            conn.close()
            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again

            site_enc, username_enc, encrypted_pwd, url_enc = entry
            try:
                site = aes_decrypt(site_enc, vault_key).decode()
                username = aes_decrypt(username_enc, vault_key).decode()
                url = aes_decrypt(url_enc, vault_key).decode()
                password = aes_decrypt(encrypted_pwd, vault_key).decode()
            except Exception:
                print(Fore.RED + "Could not decrypt password for this entry.")
                return

            logging.info(f"Auto-login initiated for site: {site}, URL: {url}")
            print(f"Opening {site}...")
            webbrowser.open(url)
            time.sleep(3)
            pyautogui.typewrite(username)
            pyautogui.press('tab')
            pyautogui.typewrite(password)
            pyautogui.press('enter')
            print(Fore.GREEN + "Auto-login completed.")
            break  # Success
        except ValueError:
            print(Fore.RED + "Invalid input.")


#-------------------------------------------------


# Main function
def main():
    # Initialize global variables
    global last_action

    # Ensure the secure folder exists
    create_secure_folder()

    # --- DECRYPT THE DATABASE FILE BEFORE ANYTHING ELSE ---
    # Ask for master password early to get the key
    clear_screen()
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT + "\nWELCOME BACK\n\n")

    first_run = not (os.path.exists(SALT_FILE) and os.path.exists(FILE_2FA) and os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0)

    if first_run:
        print(Fore.YELLOW + "First time setup: registration required.")
        init_vault()
        print(Fore.GREEN + "Registration complete. Please restart the program.")

    
    master_pwd = getpass.getpass("Enter the master password: ")
    decrypted_salt = decrypt_salt_file(master_pwd)
    vault_key = derive_key(master_pwd, decrypted_salt)

    if os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0:
        decrypt_db_file(vault_key)

    try:
        init_sqlite_vault()
        

        # Load the username
        username = "User"
        try:
            with open(USERNAME_FILE, "r") as f:
                username = f.read().strip()
        except FileNotFoundError:
            logging.warning("Username file not found. Defaulting to 'User'.")

        log_key = derive_key(master_pwd + "LOGS", decrypted_salt)
        setup_logging(log_key)

        if not verify_2fa_code(master_pwd, decrypted_salt):
            print(Fore.RED + "2FA verification failed.")
            logging.error("2FA verification failed.")
            exit(1)

        log_user_info()

        # Setting up the progress bar
        steps = [
            "Deriving the vault key...",
            "Loading the vault..."
        ]
        
        progress_bar = tqdm.tqdm(steps, desc="Loading", ascii=True, ncols=75, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}")
        
        # Decrypt the salt file
        try:

            # Step 1: Derive the vault key
            progress_bar.set_description(steps[0])
            vault_key = derive_key(master_pwd, decrypted_salt)
            progress_bar.update(1)

            # Step 2: Load the vault
            progress_bar.set_description(steps[1])
            vault = load_vault_sqlite(vault_key)
            progress_bar.update(1)

        except ValueError as ve:
            progress_bar.close()
            print(Fore.RED + f"Error: {ve}")
            logging.error(f"Error during loading: {ve}")
            exit(1)
        except RuntimeError as re:
            progress_bar.close()
            print(Fore.RED + f"Unexpected error: {re}")
            logging.error(f"Unexpected error during loading: {re}")
            exit(1)
        except Exception as e:
            progress_bar.close()
            print(Fore.RED + f"Unexpected error: {e}")
            logging.error(f"Unexpected error during loading: {e}")
            exit(1)

        progress_bar.close()
        print(Fore.GREEN + "Loading completed successfully.")
        time.sleep(1)
        try:
            while True:
                check_and_reset_timer()

                clear_screen()
                show_title()

                print(Fore.MAGENTA + Style.BRIGHT +"\nMAIN MENU                                Hi "+f"{username}\n")
                print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE +  " Add an account")
                print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE +  " Manage accounts")
                print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE +  " Advanced options")
                print(Fore.RED + "\n[0] Exit\n")
                choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

                if choice == "1":
                    add_entry(vault_key)
                elif choice == "2":
                    manage_entries(vault_key)
                elif choice == "3":
                    advanced_options(log_key,master_pwd,decrypted_salt)
                elif choice == "0":
                    logging.info("User logged out.")
                    break
        except Exception as e:
            logging.error(f"Unexpected error in main loop: {e}")
    finally:
        logging.info("Session ended.")
        backup_logs()  # Back up logs at the end of the session

        # --- ENCRYPT THE DATABASE FILE BEFORE EXIT ---
        encrypt_db_file(vault_key)
        

if __name__ == "__main__": 
    main()