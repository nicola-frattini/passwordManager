import base64
import keyring
from colorama import Fore
import logging


from src.Utils.config import SERVICE_NAME
from src.Cryptography.keyDerivation import derive_key, get_encryption_key
from src.Cryptography.saltManagment import get_salt_encryption_key





def verify_keyring_consistency(master_password: str, salt: bytes) -> bool:
    """Verify if keyring keys are consistent with current PEPPER"""
    try:
        # Get current derived keys
        current_encryption_key = derive_key(master_password, salt)
        current_salt_key = derive_key(master_password, salt)
        
        # Get stored keys from keyring
        stored_encryption = keyring.get_password(SERVICE_NAME, "encryption_key")
        stored_salt = keyring.get_password(SERVICE_NAME, "salt_encryption_key")
        
        if not stored_encryption or not stored_salt:
            return False
        
        # Compare keys
        stored_enc_decoded = base64.urlsafe_b64decode(stored_encryption)
        stored_salt_decoded = base64.urlsafe_b64decode(stored_salt)
        
        return (stored_enc_decoded == current_encryption_key and 
                stored_salt_decoded == current_salt_key)
    except Exception:
        return False

def auto_fix_keyring_if_needed(master_password: str, salt: bytes):
    """Automatically fix keyring if keys are inconsistent"""
    if not verify_keyring_consistency(master_password, salt):
        print(Fore.YELLOW + "Detecting inconsistent keyring keys. Auto-fixing...")
        
        try:
            # Clear old keys
            keyring.delete_password(SERVICE_NAME, "encryption_key")
            keyring.delete_password(SERVICE_NAME, "salt_encryption_key")
        except:
            pass  # Keys might not exist
        
        # Force regeneration by calling the functions
        get_encryption_key(master_password, salt)
        get_salt_encryption_key(master_password, salt)
        
        print(Fore.GREEN + "Keyring keys regenerated successfully.")
        logging.info("Keyring keys auto-fixed due to inconsistency.")

