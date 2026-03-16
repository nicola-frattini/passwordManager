import time
import logging
import os
import socket

from src.GUI.GUIFunctions import clear_screen
from colorama import Fore


from src.Utils.config import SESSION_TIMEOUT, USERNAME_FILE

# Initialize the last action time
last_action = time.time()


# Check for session timeout
def check_and_reset_timer():
  
    global last_action  # Use the global variable to track the last action time
    remaining_time = SESSION_TIMEOUT - (time.time() - last_action) # Calculate remaining time
    
    # Check if the session has expired
    if remaining_time <= 0:
        clear_screen()
        print(Fore.RED + "Session expired due to inactivity.")
        logging.info("Session expired due to inactivity.")
        exit(0)  # Exit the program if the session has expired
    last_action = time.time()  # Reset the timer

#======================================


# Log user information
def log_user_info():

    try:
        with open(USERNAME_FILE, "r") as f:
            account = f.read().strip()  # Read the account name from the file
    except Exception as e:
        account = "Unknown"  # Default to "Unknown" if the file is not found

    try:
        username = os.getlogin()
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        logging.info(f"Account: {account} User: {username}, Hostname: {hostname}, IP: {ip_address}")

    except Exception as e:
        logging.warning(f"Could not retrieve user information: {e}")

# ======================================
