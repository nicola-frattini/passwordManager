from src.Utils.config import *

import os
import time
import getpass
import logging
import sqlite3
import tempfile

from hashlib import sha256


from colorama import Fore, Back, Style, init
from tqdm import tqdm

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from argon2.low_level import hash_secret_raw, Type

# Refactoring import
from src.GUI.GUIFunctions import show_title, clear_screen
from src.Utils.inputs import get_valid_input
from src.Cryptography.encryption import aes_encrypt
from src.Cryptography.decryption import aes_decrypt
from src.GUI.menus import manage_entries, advanced_options
from src.Utils.session import check_and_reset_timer, log_user_info
from src.Utils.entriesManagement import add_entry
from src.Cryptography.keyDerivation import derive_key, get_encryption_key, get_salt_encryption_key, get_machine_pepper
from src.Log.logging import setup_logging
from src.Files.folderManagement import create_secure_folder, create_backup_folder
from src.Cryptography.hmacManagement import compute_hmac, save_hmac, load_hmac
from src.Files.vaultManagement import decrypt_db_file, init_vault
from src.Utils.twoFA import verify_2fa_code

# Initialize colorama to automatically reset text color/style after each print
init(autoreset=True)

#-------------------------------------------------



# Main function
def main():
    # Initialize global variables
    global last_action

    # Ensure the secure folder exists
    create_secure_folder()

    clear_screen()
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT + "\nWELCOME BACK\n\n")

    create_backup_folder() # Create the backup folder for logs
    create_secure_folder()


    first_run = not (os.path.exists(SALT_FILE) and os.path.exists(FILE_2FA) and os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0)

    if first_run:
        init_vault()

    master_pwd = getpass.getpass("Enter the master password: ")

    # Verifica MFA PRIMA di qualsiasi decifratura o fix
    # Prova a caricare il salt in chiaro solo per la verifica MFA
    try:
        with open(SALT_FILE, "rb") as f:
            encrypted_salt = f.read()
        # Prova a derivare la chiave per decriptare il salt
        salt_key = get_salt_encryption_key(master_pwd, encrypted_salt)
        plain_salt = aes_decrypt(encrypted_salt, salt_key)
    except Exception:
        print(Fore.RED + "\n[ERRORE] Impossibile decifrare il file salt: chiave errata o file corrotto.")
        print(Fore.YELLOW + "Se hai cambiato la master password, o il file salt è stato sovrascritto, non sarà possibile recuperare le password salvate.")
        exit(1)

    # Verifica MFA
    if not verify_2fa_code(master_pwd, plain_salt):
        print(Fore.RED + "\n[ERRORE] MFA fallito. Nessuna modifica effettuata. Riprova.")
        exit(1)

    # Solo ora procedi con la logica esistente
    try:
        decrypted_salt = plain_salt
    except ValueError:
        print(Fore.RED + "\n[ERRORE] Decifratura fallita anche dopo l'auto-fix. Se il problema persiste, il file salt è corrotto o la master password è errata.")
        print(Fore.YELLOW + "Se non hai backup, dovrai re-inizializzare il vault e perderai tutte le password salvate.")
        exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[ERRORE] Errore inatteso: {e}")
        exit(1)

    # Deriva la chiave del vault
    vault_key = derive_key(master_pwd, decrypted_salt)

    # Decripta il vault se esiste
    decrypted_data = None
    if os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0:
        decrypted_data = decrypt_db_file(vault_key)
        if decrypted_data is None:
            print(Fore.RED + "Cannot open vault due to integrity issues. Contact administrator or restore from backup.")
            logging.error("Vault integrity error: user notified.")
            input("\nPress Enter to exit...")
            exit(1)

    # Create the vault in RAM
    conn = sqlite3.connect(":memory:")
    if decrypted_data:
        # Load decrypted database into RAM
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(decrypted_data)
            tmp.flush()
            tmp_path = tmp.name
        disk_conn = sqlite3.connect(tmp_path)
        for line in disk_conn.iterdump():
            if line not in ('BEGIN;', 'COMMIT;'):
                conn.execute(line)
        disk_conn.close()
        os.remove(tmp_path)
    else:
        # If it doesn't exist, create the table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                url TEXT,
                note TEXT
            )
        """)

    try:
        # Load the username
        username = "User"
        try:
            with open(USERNAME_FILE, "r") as f:
                username = f.read().strip()
        except FileNotFoundError:
            logging.warning("Username file not found. Defaulting to 'User'.")

        log_key = derive_key(master_pwd + "LOGS", decrypted_salt)
        setup_logging(log_key)

        log_user_info()

        clear_screen()
        show_title()
        print(Fore.GREEN + f"\nWelcome back, {username}!")
        print(Fore.GREEN + "Password Manager loaded successfully.")
        time.sleep(2)

        # Main menu loop
        while True:
            check_and_reset_timer()
            clear_screen()
            show_title()
            print(Fore.MAGENTA + Style.BRIGHT + f"\nMAIN MENU                          {username}\n")
            print(Fore.LIGHTMAGENTA_EX + "[1]" + Fore.WHITE + " Add a new account")
            print(Fore.LIGHTMAGENTA_EX + "[2]" + Fore.WHITE + " Manage accounts")
            print(Fore.LIGHTMAGENTA_EX + "[3]" + Fore.WHITE + " Advanced options")
            print(Fore.RED + "\n[0] Exit\n")
            
            choice = get_valid_input("> ", valid_options=["0", "1", "2", "3", "4"])

            if choice == "1":
                add_entry(conn, vault_key)
            elif choice == "2":
                manage_entries(conn, vault_key)
            elif choice == "3":
                advanced_options(log_key, master_pwd, decrypted_salt)
            elif choice == "0":
                print(Fore.YELLOW + "Exiting...")
                break

    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram interrupted by user.")
        logging.info("Program interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}")
        logging.error(f"Unexpected error in main: {e}")
    finally:
        # Save the vault back to disk (encrypted)
        try:
            conn.commit()
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                backup_conn = sqlite3.connect(tmp.name)
                try:
                    conn.backup(backup_conn)
                finally:
                    backup_conn.close()
                with open(tmp.name, "rb") as f:
                    plain_data = f.read()
            
            encrypted = aes_encrypt(plain_data, vault_key)
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypted)
            
            hmac_value = compute_hmac(encrypted, vault_key)
            save_hmac(hmac_value, HMAC_FILE)
            os.remove(tmp.name)
            
            logging.info("Vault saved and encrypted successfully.")
        except Exception as e:
            print(Fore.RED + f"\n[!] Error during vault backup: {e}")
            logging.error(f"Error during vault backup: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
