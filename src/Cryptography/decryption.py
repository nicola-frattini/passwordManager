import os
import logging
import hmac


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from colorama import Fore

from src.Utils.config import VAULT_FILE, HMAC_FILE
from src.Cryptography.hmacManagement import compute_hmac, load_hmac



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


# =======================================
