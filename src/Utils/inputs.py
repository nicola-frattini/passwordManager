from colorama import Fore


# Use to get a valid input from the user
def get_valid_input(prompt: str, valid_options: list = None, allow_empty: bool = False) -> str:
# Prompt str - The message to display to the user
# Valid_options list - A list of valid options for the user to choose from (optional)
# allow_empty bool - Whether to allow empty input (default: False)
# Returns the user's input as a string
    
    while True:
        user_input = input(prompt).strip() # Get user input and remove leading/trailing spaces
        if allow_empty and user_input == "": # Allow empty input if specified
            return user_input 
        if valid_options and user_input not in valid_options:  # Check if the input is in the list of valid options
            print(Fore.RED + f"Invalid input. Please choose from: {', '.join(valid_options)}")
            continue
        return user_input
    

