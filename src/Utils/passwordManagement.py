import secrets
import string
import logging
import requests
import hashlib
from tqdm import tqdm
from colorama import Fore, Style


from src.Utils.config import PASSWORD_LENGTH_DEFAULT
from src.GUI.GUIFunctions import clear_screen, show_title
from src.Cryptography.decryption import aes_decrypt


# Generate a random 
def generate_password(length: int = PASSWORD_LENGTH_DEFAULT,include_special_chars:bool = True) -> str:
# length - The length of the password to generate (default: 16)
# include_special_chars - Whether to include special characters (default: True)


    if length < 8:
        print(" Minimum password's length is 8 char.")
        return ""
    
    #Check for special characters
    mandatory_special_character = "@#!+=_-"
    characters = string.ascii_letters + string.digits
    if include_special_chars:
        characters += mandatory_special_character

    # Generate a random password
    password = ''.join(secrets.choice(characters) for _ in range(length)) # Generate a random password using the specified characters
    return password



# Check if the password has been compromised using HIBP API for all passwords in the vault
def check_vault_passwords(conn,vault_key: bytes):
# conn - The SQLite connection object
# vault_key - The encryption key used to encrypt the vault

    logging.info("Checking passwords in the vault...")
    
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        return

    clear_screen()
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT + "\nCHECK PASSWORDS\n")
    print("\nChecking passwords in the vault...\n")


    # Initialize a list to store results
    results = []

    # Loop through each entry in the vault and check the password
    with tqdm(rows, desc="Checking passwords", ascii=True, ncols=75, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}") as progress_bar:
        for row in progress_bar:
            try:
                decrypted_pwd = aes_decrypt(row[3], vault_key).decode()
            except Exception:
                decrypted_pwd = "<decryption error>"

            if decrypted_pwd != "<decryption error>" and check_password_hibp(decrypted_pwd) != 0:
                try:
                    site = aes_decrypt(row[1], vault_key).decode()
                except Exception:
                    site = "<decryption error>"
                results.append((site, Fore.RED + f"WARNING: The password for {site} has been compromised! Change it immediately."))
                logging.warning(f"Password for {site} has been compromised!")

    print(Fore.GREEN + "\nPassword check completed.\n")
    if results:
        for site, message in results:
            print(message)
    else:
        print(Fore.GREEN + "No compromised passwords found in the vault.")

    input("\nPress Enter to return to the menu...")


# =======================================


# Check if the password has been compromised using HIBP API
def check_password_hibp(password: str) -> int:
# password - The password to check

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper() # Hash the password using SHA1
    prefix, suffix = sha1_hash[:5], sha1_hash[5:] #Split the hash into prefix and suffix

    # Query the HIBP API with the first 5 characters of the hash
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print(Fore.RED + f"Error fetching data from HIBP API: {response.status_code}")
            return 0

        # Check if the suffix exists in the response
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                logging.warning(f"Password found in {count} breaches!")
                return {count}

        return 0
    except requests.RequestException as e:
        logging.error(f"Error connecting to HIBP API: {e}")
        print(Fore.RED + f"Error connecting to HIBP API: {e}")
        return 0


#======================================