import sqlite3
import logging
import hmac
import os
import hashlib
import getpass

from colorama import Fore, Style


from src.Utils.config import VAULT_FILE, HMAC_FILE, SALT_FILE, USERNAME_FILE, FILE_2FA
from src.GUI.GUIFunctions import clear_screen, show_title
from src.Utils.inputs import get_valid_input
from src.Cryptography.encryption import aes_encrypt
from src.Cryptography.decryption import aes_decrypt
from src.Cryptography.hmacManagement import compute_hmac, save_hmac, load_hmac
from src.Utils.twoFA import setup_2fa
from src.Cryptography.keyDerivation import derive_key
from src.Cryptography.saltManagement import decrypt_salt_file, encrypt_salt_file



def init_sqlite_vault():
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL,
            url TEXT,
            note TEXT
        )
    """)
    # Aggiorna la tabella se manca la colonna note
    try:
        cursor.execute("ALTER TABLE vault ADD COLUMN note TEXT")
    except sqlite3.OperationalError:
        pass  # La colonna esiste già
    conn.commit()
    conn.close()

#======================================


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

# ======================================

def encrypt_db_file(key: bytes):
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    encrypted = aes_encrypt(data, key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)
    # Compute the HMAC of the encrypted data
    hmac_value = compute_hmac(encrypted, key)
    save_hmac(hmac_value, HMAC_FILE)  # Save the HMAC to a file

# ======================================

def decrypt_db_file(key: bytes) -> bytes | None: 
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()

    # Verify the HMAC of the encrypted data
    try:
        # Load the expected HMAC from the file
        expected_hmac = load_hmac(HMAC_FILE)
    except FileNotFoundError:
        print(Fore.RED + "HMAC file not found. Vault integrity cannot be verified!")
        return False
    # Verify the HMAC
    actual_hmac = compute_hmac(encrypted, key)
    if not hmac.compare_digest(expected_hmac, actual_hmac):
        print(Fore.RED + "Vault integrity check failed! The file may have been tampered with.")
        logging.warning("Vault integrity check failed! The file may have been tampered with.")
        return False
    
    return aes_decrypt(encrypted, key)  # Decrypt the vault file

# ======================================

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


# ======================================


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
