import os
from colorama import Fore

from src.Utils.config import SALT_FILE
from src.Cryptography.encryption import aes_encrypt
from src.Cryptography.decryption import aes_decrypt
from src.Cryptography.keyDerivation import get_salt_encryption_key


# Decrypt the salt file using the master password and the key from the keyring
def decrypt_salt_file(master_password: str) -> bytes:
# master_password - The master password used for key derivation


    # Check if the salt file exists
    try:
        with open(SALT_FILE, "rb") as f:
            encrypted_salt = f.read()
        salt_key = get_salt_encryption_key(master_password, encrypted_salt)
        return aes_decrypt(encrypted_salt, salt_key)
    except ValueError as ve:
        print(Fore.RED + "\n[ERRORE] Impossibile decifrare il file salt: chiave errata o file corrotto.")
        print(Fore.YELLOW + "Se hai cambiato la master password, o il file salt è stato sovrascritto, non sarà possibile recuperare le password salvate.")
        raise ve
    except Exception as e:
        print(Fore.RED + f"\n[ERRORE] Errore inatteso durante la decifratura del salt: {e}")
        raise e



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


# =======================================