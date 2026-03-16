import os
import logging
from colorama import Fore


from src.Utils.config import VAULT_FILE, HMAC_FILE



def import_vault():
    try:
        print(Fore.MAGENTA + "\nIMPORT VAULT\n")
        import_path = input("Enter the path of the vault file to import: ").strip()
        if not import_path or not os.path.exists(import_path):
            print(Fore.RED + "File not found. Import cancelled.")
            return

        # Ask the user for the HMAC file path (optional)
        import_hmac_path = input("Enter the path of the HMAC file to import (or leave blank to skip): ").strip()
        # Fai un backup del vault attuale prima di sovrascrivere
        if os.path.exists(VAULT_FILE):
            backup_path = VAULT_FILE + ".bak"
            with open(VAULT_FILE, "rb") as src, open(backup_path, "wb") as dst:
                dst.write(src.read())
            print(Fore.YELLOW + f"Current vault backed up to {backup_path}")

        # Copy the vault file to the destination
        with open(import_path, "rb") as src, open(VAULT_FILE, "wb") as dst:
            dst.write(src.read())
        print(Fore.GREEN + "Vault file imported successfully.")

        # Copy the HMAC file if provided
        if import_hmac_path and os.path.exists(import_hmac_path):
            with open(import_hmac_path, "rb") as src, open(HMAC_FILE, "wb") as dst:
                dst.write(src.read())
            print(Fore.GREEN + "HMAC file imported successfully.")
        elif import_hmac_path:
            print(Fore.YELLOW + "HMAC file not found, skipped.")

        print(Fore.GREEN + "Import completed. Please restart the program to load the new vault.")
        input("\nPress Enter to return to the menu...")

    except Exception as e:
        print(Fore.RED + f"Error importing vault: {e}")
        logging.error(f"Error importing vault: {e}")
        input("\nPress Enter to return to the menu...")

