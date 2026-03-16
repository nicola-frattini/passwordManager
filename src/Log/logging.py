from colorama import Fore, Style
import logging
import os
import time


from src.Utils.config import LOG_FILE, LOG_BACKUP_FOLDER, BACKUP_RETENTION_DAYS
from src.Cryptography.decryption import aes_decrypt
from src.GUI.GUIFunctions import clear_screen, show_title   
from src.Log.EncryptedLogHandler import EncryptedLogHandler
from src.Files.folderManagement import create_backup_folder


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
                        color = Fore.RED
                    elif " - ERROR - " in decrypted_str:
                        color = Fore.YELLOW
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



# =======================================


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

# =======================================