import threading
import time
import logging
import pyperclip
import getpass
import webbrowser
import pyautogui


from src.Cryptography.encryption import aes_encrypt
from src.Cryptography.decryption import aes_decrypt
from src.Utils.session import check_and_reset_timer
from src.GUI.GUIFunctions import clear_screen, show_title
from colorama import Fore, Style
from src.Utils.inputs import get_valid_input
from src.Utils.passwordManagement import generate_password



# Show all entries in the vault
def show_entries(conn,vault_key: bytes, copy_enabled=True, justView_enabled=True):
    check_and_reset_timer()
    clear_screen()

    # Load the vault from the file

    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url, note FROM vault")
    rows = cursor.fetchall()

    # Check if the vault is empty
    if not rows:
        print(Fore.RED + "\nThe vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return
    
    # Print the entries in a formatted way
    show_title()
    print(Fore.MAGENTA + Style.BRIGHT + "\nACCOUNT LIST\n")
    print(Fore.MAGENTA + "{:<5} {:<20} {:<20} {:<20} {:<30}".format("ID", "Site", "Username", "Password", "Note"))
    print(Fore.MAGENTA + "-" * 110)

    decrypted_rows = []
    for row in rows:
        try:
            decrypted_site = aes_decrypt(row[1], vault_key).decode()
            decrypted_user = aes_decrypt(row[2], vault_key).decode()
            decrypted_pwd = aes_decrypt(row[3], vault_key).decode()
            decrypted_url = aes_decrypt(row[4], vault_key).decode()
            decrypted_note = aes_decrypt(row[5], vault_key).decode() if row[5] else ""
        except Exception:
            decrypted_site = "<decryption error>"
            decrypted_user = "<decryption error>"
            decrypted_pwd = "<decryption error>"
            decrypted_url = "<decryption error>"
            decrypted_note = "<decryption error>"
        decrypted_rows.append((row[0], decrypted_site, decrypted_user, decrypted_pwd, decrypted_url, decrypted_note))
        print(Fore.WHITE + "{:<5} {:<20} {:<20} {:<20} {:<30}".format(row[0], decrypted_site, decrypted_user, '*' * 10, decrypted_note))

    logging.info(f"Viewed entries")
    print("\n")

    if copy_enabled:
        while True:
            try:
                copy = input("\nDo you want to copy a password? Enter the ID or press Enter to skip: ").strip()
                if not copy:
                    # If user presses Enter, return to the previous menu
                    return
                idx = int(copy)
                for entry in decrypted_rows:
                    if entry[0] == idx:
                        pyperclip.copy(entry[3])
                        logging.info(f"Copied password for site: {entry[1]}")
                        print(Fore.GREEN + "Password copied to clipboard, it will be erased in 30 seconds for security.")
                        def clear_clipboard():
                            time.sleep(30)
                            pyperclip.copy("")
                        threading.Thread(target=clear_clipboard, daemon=True).start()
                        input("\nPress Enter to return to the menu...")
                        return  # Success, exit the loop and function
                print(Fore.RED + "Invalid ID. Please try again.")
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a valid number or press Enter to cancel.")

    if justView_enabled:
        input("\nPress Enter to return to the menu...")

#========================================


# Edit an entry
def edit_entry(conn,vault_key: bytes):
# conn- The SQLite connection object
# vault_key - The encryption key used to encrypt the vault

    # Check if the vault is empty

    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(conn,vault_key, copy_enabled=False, justView_enabled=False)

    try:
        while True:
            idx = get_valid_input("Enter the account ID to edit (leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                break
            try:
                idx = int(idx)
            except ValueError:
                print("Invalid input. Please enter a valid number.")
                continue
            cursor.execute("SELECT id, site, username, password, url FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()
            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again

            try:
                decrypted_site = aes_decrypt(entry[1], vault_key).decode()
                decrypted_user = aes_decrypt(entry[2], vault_key).decode()
                decrypted_pwd = aes_decrypt(entry[3], vault_key).decode()
                decrypted_url = aes_decrypt(entry[4], vault_key).decode()
            except Exception:
                print(Fore.RED + "Could not decrypt one or more fields for this entry.")
                continue

            print(f"Editing {decrypted_site}")
            new_user = get_valid_input(f"New username (leave blank to keep '{decrypted_user}'): ", allow_empty=True)
            new_url = get_valid_input(f"New URL (leave blank to keep '{decrypted_url}'): ", allow_empty=True)
            new_note = get_valid_input(f"New Note (leave blank to keep): ", allow_empty=True)
            print("\n[1] Keep the current password\n[2] Manually enter a new password\n[3] Generate a new password\n[0] Cancel")
            choice = get_valid_input("> ", valid_options=["0", "1", "2", "3"])

            new_pwd = None
            if choice == "0":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                break
            elif choice == "2":
                new_pwd = getpass.getpass("New password (or leave blank to cancel): ").strip()
                if not new_pwd:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    break
            elif choice == "3":
                length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                if not length:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    break
                length = int(length) if length.isdigit() else 24
                include_special_chars = get_valid_input("Include special characters? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
                if not include_special_chars:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    break
                new_pwd = generate_password(length)
                print(f"Generated password: {new_pwd}")

            if new_user:
                encrypted_user = aes_encrypt(new_user.encode(), vault_key)
                cursor.execute("UPDATE vault SET username=? WHERE id=?", (encrypted_user, idx))
            if new_url:
                encrypted_url = aes_encrypt(new_url.encode(), vault_key)
                cursor.execute("UPDATE vault SET url=? WHERE id=?", (encrypted_url, idx))
            if new_pwd:
                encrypted_pwd = aes_encrypt(new_pwd.encode(), vault_key)
                cursor.execute("UPDATE vault SET password=? WHERE id=?", (encrypted_pwd, idx))
            if new_note:
                encrypted_note = aes_encrypt(new_note.encode(), vault_key)
                cursor.execute("UPDATE vault SET note=? WHERE id=?", (encrypted_note, idx))
            conn.commit()
            print(Fore.GREEN + "Account updated.")
            logging.info(f"Edited entry for site: {decrypted_site}, url: {decrypted_url}")
            input("\nPress Enter to return to the menu...")
    except Exception as e:
        print(Fore.RED + f"Unexpected error editing entry: {e}")

#=================================================


# Delete an entry
def delete_entry(conn,vault_key: bytes):
# conn - The SQLite connection object
# vault_key - The encryption key used to encrypt the vault

    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(conn,vault_key, copy_enabled=False, justView_enabled=False)

    while True:
        try:
            idx = get_valid_input("ID to delete (or leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            idx = int(idx)
            cursor.execute("SELECT id, site FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()
            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again
            confirm = get_valid_input(Fore.RED + f"Do you confirm the deletion of {aes_decrypt(entry[1], vault_key).decode()}? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
            if not confirm or confirm == "n":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            elif confirm == "y":
                cursor.execute("DELETE FROM vault WHERE id=?", (idx,))
                conn.commit()
                print(Fore.GREEN + "Entry deleted.")
                logging.info(f"Deleted entry with ID: {idx}")
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a valid number.")

#========================================


# Check if the session has timed out and reset the timer
def auto_login(conn,vault_key: bytes):
# conn - The SQLite connection object
# vault_key - The encryption key used to encrypt the vault

    check_and_reset_timer()

    # Load and show entries
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, url FROM vault")
    rows = cursor.fetchall()

    if not rows:
        print(Fore.RED + "The vault is empty.")
        input(Fore.WHITE + "\nPress Enter to return to the menu...")
        return

    show_entries(conn,vault_key, copy_enabled=False, justView_enabled=False)  # Show entries without copy option

    while True:
        try:
            idx = get_valid_input("Enter the account ID to auto-login (leave blank to cancel): ", allow_empty=True)
            if not idx:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            idx = int(idx)
            # Fetch the entry from the database by ID
            cursor.execute("SELECT site, username, password, url FROM vault WHERE id=?", (idx,))
            entry = cursor.fetchone()

            if not entry:
                print(Fore.RED + "Invalid ID. Please try again.")
                continue  # Ask again

            site_enc, username_enc, encrypted_pwd, url_enc = entry
            try:
                site = aes_decrypt(site_enc, vault_key).decode()
                username = aes_decrypt(username_enc, vault_key).decode()
                url = aes_decrypt(url_enc, vault_key).decode()
                password = aes_decrypt(encrypted_pwd, vault_key).decode()
            except Exception:
                print(Fore.RED + "Could not decrypt password for this entry.")
                return

            logging.info(f"Auto-login initiated for site: {site}, URL: {url}")
            print(f"Opening {site}...")
            webbrowser.open(url)
            time.sleep(3)
            pyautogui.typewrite(username)
            pyautogui.press('tab')
            pyautogui.typewrite(password)
            pyautogui.press('enter')
            print(Fore.GREEN + "Auto-login completed.")
            break  # Success
        except ValueError:
            print(Fore.RED + "Invalid input.")


#========================================


# Add a new item
def add_entry(conn,vault_key: bytes):
# conn - The SQLite connection object
# vault_key - The encryption key used to encrypt the vault

    while True:
        clear_screen()
        show_title()
        print(Fore.MAGENTA + Style.BRIGHT +"\nADD A NEW ACCOUNT\n")
        check_and_reset_timer()

        try:
            site = get_valid_input("Site (or leave blank to cancel): ", allow_empty=True)
            if not site:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            user = get_valid_input("Username (or leave blank to cancel): ", allow_empty=True)
            if not user:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            url = get_valid_input("URL (or leave blank to cancel): ", allow_empty=True)
            if not url:
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return

            note = get_valid_input("Notes (optional): ", allow_empty=True)

            print("\n[1] Set manually a password\n[2] Generate a secure password\n\n[0] Cancel")
            choice = get_valid_input("> ", valid_options=["0", "1", "2"])

            if choice == "0":
                print(Fore.RED + "cancelled...")
                time.sleep(2)
                return
            elif choice == "1":
                pwd = getpass.getpass("Password (or leave blank to cancel): ").strip()
                if not pwd:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
            elif choice == "2":
                length = get_valid_input("Password length (default 24, or leave blank to cancel): ", allow_empty=True)
                if not length:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
                length = int(length) if length.isdigit() else 24
                include_special_chars = get_valid_input("Include special characters? (y/n, or leave blank to cancel): ", valid_options=["y", "n"], allow_empty=True)
                if not include_special_chars:
                    print(Fore.RED + "cancelled...")
                    time.sleep(2)
                    return
                pwd = generate_password(length, include_special_chars == "y")
                print(Fore.GREEN + f"Password generated: {pwd}")

            # Encrypt all fields before storing
            cursor = conn.cursor()
            encrypted_site = aes_encrypt(site.encode(), vault_key)
            encrypted_user = aes_encrypt(user.encode(), vault_key)
            encrypted_pwd = aes_encrypt(pwd.encode(), vault_key)
            encrypted_url = aes_encrypt(url.encode(), vault_key)
            encrypted_note = aes_encrypt(note.encode(), vault_key) if note else b''
            cursor.execute(
                "INSERT INTO vault (site, username, password, url, note) VALUES (?, ?, ?, ?, ?)",
                (encrypted_site, encrypted_user, encrypted_pwd, encrypted_url, encrypted_note)
            )
            conn.commit()

            print(Fore.GREEN + "Credentials entered correctly.")
            logging.info(f"Added new entry for site: {site}, url: {url}")
            break

        except ValueError:
            print(Fore.RED + "Invalid input. Please try again.")
            logging.error("ValueError occurred while adding an entry.")
        except Exception as e:
            print(Fore.RED + f"Unexpected error adding an entry: {e}")
            logging.error(f"Unexpected error: {e}")

    input("\nPress Enter to return to the menu...")


# =======================================