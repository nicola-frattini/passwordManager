import os
import logging
import pyotp
import qrcode
from colorama import Fore


from src.Utils.config import FILE_2FA, USERNAME_FILE
from src.Cryptography.encryption import aes_encrypt
from src.Cryptography.decryption import aes_decrypt
from src.Cryptography.keyDerivation import derive_key
from src.Utils.inputs import get_valid_input



# Setup 2FA using TOTP
def setup_2fa(master_password: str, salt: bytes):
    
    secret_key= pyotp.random_base32()  # Generate a random base32 secret key

    # Load the username
    username = "User"
    try:
        with open(USERNAME_FILE, "r") as f:
            username = f.read().strip()
    except FileNotFoundError:
        logging.warning("Username file not found. Defaulting to 'User'.")


    # Generate a QR code for the TOTP secret key
    totp = pyotp.TOTP(secret_key)
    qr_code_url = totp.provisioning_uri(name="PasswordManager", issuer_name=f"{username}")  # Generate the provisioning URI for the QR code

    # Display the QR code
    print(Fore.MAGENTA + "\nScan the QR code with your authenticator app:\n")
    qr = qrcode.QRCode()
    qr.add_data(qr_code_url)
    qr.make(fit=True)

    # Print the QR code in ASCII format
    qr.print_ascii()

    print("\nOr manually enter this key in your authenticator app: " + f"{secret_key}")

    print(Fore.RED + "\n!! This is the only opportunity to get the code. If you don't do it now, it will be lost forever.")
    input("\nPress Enter to continue...")  # Wait for user input

    
    # Encrypt the secret key
    encryption_key = derive_key(master_password, salt)
    encrypted_secret_key = aes_encrypt(secret_key.encode(), encryption_key)

    # Save the encrypted secret key to the file
    with open(FILE_2FA, "wb") as f:
        f.write(encrypted_secret_key)
    
    print(Fore.GREEN + "\n2FA setup complete.")   


#--------------------------------------------------


# Verify the 2FA code
def verify_2fa_code(master_password: str, salt: bytes) -> bool:

    try:

         # Check if the 2FA secret file exists
 
        if not os.path.exists(FILE_2FA):
            print(Fore.RED + "2FA secret key file not found. Please set up 2FA first.")
            logging.error("2FA secret key file not found.")
            return False

        # Load the secret key from the file
        with open(FILE_2FA, "rb") as f:
            encrypted_secret_key = f.read().strip()

        # Decrypt the secret key
        decryption_key = derive_key(master_password, salt)
        secret_key = aes_decrypt(encrypted_secret_key, decryption_key).decode()


        # Prompt the user for the 2FA code
        totp = pyotp.TOTP(secret_key)
        for attempt in range(1, 4): # Allow 3 attempts
            user_code = get_valid_input("Enter the 2FA code: ", allow_empty=False)

            # Verify the 2FA code
            if totp.verify(user_code):
                print(Fore.GREEN + "2FA code verified successfully.")
                logging.info("2FA code verified successfully.")
                return True

            else:
                print(Fore.RED + "Invalid 2FA code. please try again.")
                logging.warning("Invalid 2FA code.")

        # If all attempts fail
        print(Fore.RED + "2FA verification failed. Please try again later.")
        logging.error("2FA verification failed after 3 attempts.")
        return False
        
    except FileNotFoundError:
        print(Fore.RED + "2FA secret key file not found. Please set up 2FA first.")
        logging.error("2FA secret key file not found.")
        return False
    except Exception as e:
        print(Fore.RED + f"Error verifying 2FA code: {e}")
        logging.error(f"Error verifying 2FA code: {e}")
        return False

