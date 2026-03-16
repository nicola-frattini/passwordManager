import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7


# ============================= CRYPTOGRAPHY FUNCTIONS =============================


# Encrypt data using AES-256 with the provided key
def aes_encrypt(data: bytes, key: bytes) -> bytes:
# data - The plaintext data to encrypt
# key - The 256-bit encryption key


    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to make it a multiple of the block size (16 bytes)
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the ciphertext
    return iv + ciphertext
