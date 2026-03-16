import hmac
import hashlib


# Function for the HMAC (Hash-based Message Authentication Code)

# compute the HMAC of the data using the provided key
def compute_hmac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# Verify the HMAC of the data using the provided key
def save_hmac(hmac_value: bytes, hmac_file: str):
    with open(hmac_file, "wb") as f:
        f.write(hmac_value)

# Load the HMAC from a file
def load_hmac(hmac_file: str) -> bytes:
    with open(hmac_file, "rb") as f:
        return f.read()
