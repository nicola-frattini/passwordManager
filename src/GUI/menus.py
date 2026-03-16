import time

from colorama import Fore, Style

from src.Utils.config import LOG_FILE
from src.Cryptography.decryption import aes_decrypt
from src.GUI.GUIFunctions import clear_screen, show_title
from src.Utils.inputs import get_valid_input
from src.Utils.session import check_and_reset_timer
from src.Log.logging import export_logs, decrypt_logs
from src.Utils.entriesManagement import show_entries, edit_entry, delete_entry, auto_login
from src.Utils.passwordManagement import check_vault_passwords
from src.Files.exports import export_keys, export_vault
from src.Files.imports import import_vault


# Manage entries in the vault
def manage_entries(conn,vault_key: bytes):
# conn - The SQLite connection object
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
            show_entries(conn,vault_key, copy_enabled=False)
        elif choice == "2":
            show_entries(conn,vault_key, copy_enabled=True, justView_enabled=False)
        elif choice == "3":
            edit_entry(conn,vault_key)
        elif choice == "4":
            delete_entry(conn,vault_key)
        elif choice == "5":
            auto_login(conn,vault_key)
        elif choice == "6":
            check_vault_passwords(conn,vault_key)
        elif choice == "0":
            break



#========================================

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


# =======================================


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


# =======================================


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
        print(Fore.LIGHTMAGENTA_EX + "[4]" + Fore.WHITE +  " Import crypted vault backup")    
        print(Fore.RED + "\n[0] Return to the menu\n")
        choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

        if choice == "1":
            export_keys(input("Enter the path to export the keys (default C:/user/documenti/backup_keys.txt): ").strip(),master_pwd,salt)
        elif choice == "2":
            log_view_menu(LOG_FILE, log_key)
        elif choice == "3":
            export_vault()
        elif choice == "4":
            import_vault()
        elif choice == "0":
            break


#========================================