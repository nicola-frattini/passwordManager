
import os
import base64
import keyring
import logging
import uuid
import socket
import stat

from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import hash_secret_raw, Type


from src.Utils.config import SERVICE_NAME, PEPPER_FILE

# Derive a key from the master password and salt
def derive_key(master_password: str, salt: bytes) -> bytes:
# master_password - The master password used for key derivation
# salt - The salt used for key derivation
    
    
    master_password += get_machine_pepper() # Combine the master password with PEPPER
    
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


# ======================================


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

# ======================================



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


# =======================================



# Derive PEPPER from the machine's unique identifier
def get_machine_pepper() -> str:
    pepper_file = os.path.join(PEPPER_FILE)
    
    # Se il file PEPPER già esiste, caricalo
    if os.path.exists(pepper_file):
        try:
            with open(pepper_file, "r") as f:
                return f.read().strip()
        except Exception as e:
            logging.warning(f"Could not read pepper file: {e}")
    
    # Altrimenti generalo e salvalo
    machine_id = str(uuid.getnode()) + socket.gethostname()
    pepper = sha256(machine_id.encode()).hexdigest()
    
    try:
        # Assicurati che la directory esista
        os.makedirs(os.path.dirname(pepper_file), exist_ok=True)
        with open(pepper_file, "w") as f:
            f.write(pepper)
        # Rendi il file accessibile solo al proprietario
        os.chmod(pepper_file, stat.S_IRUSR | stat.S_IWUSR)
        logging.info("Pepper generated and saved.")
    except Exception as e:
        logging.error(f"Could not save pepper file: {e}")
    
    return pepper


# =======================================

