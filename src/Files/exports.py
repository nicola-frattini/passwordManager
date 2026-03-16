import os
import stat
import logging
import base64
import keyring
from tqdm import tqdm
from colorama import Fore, Style

from src.Utils.config import SERVICE_NAME, VAULT_FILE, HMAC_FILE
from src.Cryptography.keyDerivation import derive_key, get_encryption_key, get_salt_encryption_key
from src.Cryptography.saltManagement import decrypt_salt_file
from src.Cryptography.decryption import aes_decrypt
from src.GUI.GUIFunctions import clear_screen, show_title



# Export all keys to a file
def export_keys(export_path: str, master_password: str,salt: bytes):
   
    try:
        
        # Set the default export path
        default_dir = os.path.join(os.path.expanduser("~"), "Documenti")
        if not os.path.exists(default_dir):
            default_dir = os.path.join(os.path.expanduser("~"), "Documents")  # fallback for non-Italian systems
        default_export_path = os.path.join(default_dir, "backup_keys.txt")

        if not export_path:
            export_path = default_export_path


        steps = [
            "Decrypting the salt file...",
            "Deriving encryption keys...",
            "Retrieving stored keys...",
            "Writing keys to the export file..."
        ]

        # Initialize the progress bar
        progress_bar = tqdm(steps, desc="Exporting Keys", ascii=True, ncols=75, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}")

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


# =======================================


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


# =======================================



# Export the vault to a user-specified location
def export_vault():
    try:
        if not os.path.exists(VAULT_FILE):
            print(Fore.RED + "Vault file not found. Please ensure the vault is initialized.")
            return

        # Ask the user for the export path (default to Documents folder)
        default_dir = os.path.join(os.path.expanduser("~"), "Documenti")
        if not os.path.exists(default_dir):
            default_dir = os.path.join(os.path.expanduser("~"), "Documents")  # fallback for non-Italian systems
        default_export_path = os.path.join(default_dir, "vault.txt")

        export_path = input(f"Enter the path to export the vault (default: {default_export_path}): ").strip()
        if not export_path:
            export_path = default_export_path

        with open(VAULT_FILE, "rb") as src, open(export_path, "wb") as dst:
            dst.write(src.read())

        # Export the HMAC file (if exists)
        hmac_export_path = export_path + ".hmac"
        if os.path.exists(HMAC_FILE):
            with open(HMAC_FILE, "rb") as src, open(hmac_export_path, "wb") as dst:
                dst.write(src.read())
            print(Fore.GREEN + f"HMAC exported successfully to {hmac_export_path}")
            logging.info(f"HMAC exported to {hmac_export_path}")
        else:
            print(Fore.YELLOW + "HMAC file not found, only vault exported.")

        
        print(Fore.GREEN + f"Vault exported successfully to {export_path}")
        logging.info(f"Vault exported to {export_path}")
    except Exception as e:
        print(Fore.RED + f"Error exporting vault: {e}")
        logging.error(f"Error exporting vault: {e}")

    input("\nPress Enter to return to the menu...")

