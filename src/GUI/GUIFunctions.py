from colorama import Fore, Style

import os


# ============================== GUI FUNCTIONS ==============================

# Show the title of the program
def show_title():
    print(Fore.MAGENTA +  Style.BRIGHT + """\n
╔────────────────────────────────────────────────────────────────────────╗
│ _____                             _      _____                         │
│|  _  |___ ___ ___ _ _ _ ___ ___ _| |    |     |___ ___ ___ ___ ___ ___ │
│|   __| .'|_ -|_ -| | | | . |  _| . |    | | | | .'|   | .'| . | -_|  _|│
│|__|  |__,|___|___|_____|___|_| |___|    |_|_|_|__,|_|_|__,|_  |___|_|  │
│                                                           |___|        │
╚────────────────────────────────────────────────────────────────────────╝\n
""" + Style.RESET_ALL)
    
    print(Fore.MAGENTA + "                                                 made by @nicola-frattini\n")


# ============================= GUI FUNCTIONS ==============================

# Clear the screen function
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

