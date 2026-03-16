import logging
from src.Cryptography.encryption import aes_encrypt
from src.Utils.config import LOG_FILE
from colorama import Fore

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
