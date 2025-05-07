# passwordManager

A secure and feature-rich password manager built with Python.                                                                            
This application allows you to securely store, manage, and generate passwords, while also providing advanced features like encrypted logging, auto-login, and integration with the Have I Been Pwned (HIBP) API to check for compromised passwords.

# Features

Secure Vault: Encrypts and stores your passwords securely using the cryptography library.                                                                                                                          
Password Generation: Generate strong, random passwords with customizable length and special characters.                                       
Encrypted Logging: Logs are encrypted to ensure sensitive information is protected.                                      
Clipboard Management: Copy passwords to the clipboard with automatic clearing after 30 seconds.                                      
Auto-Login: Simulates typing credentials into websites for quick login.                                      
HIBP Integration: Checks if your passwords have been compromised in known data breaches.                                      
Session Timeout: Automatically logs out after a period of inactivity.                                      
Backup and Export: Backup and export your vault and logs securely.                                      

# Requirements
The application requires the following Python libraries:                                      
```
cryptography==41.0.3      # For encryption, decryption, and key derivation                                      
requests==2.31.0          # For HIBP API calls                                                                            
pyperclip==1.8.2          # For clipboard operations                                                                            
pyautogui==0.9.53         # For simulating keyboard and mouse actions                                      
keyring==24.2.0           # For securely storing and retrieving keys                                      
```

# Install the dependencies using:

pip install -r requirements.txt

# Installation

### 1. Clone the repository:                
```
git clone https://github.com/your-username/passwordManager.git                                      
cd passwordManager
```                                   
### 2. Install the required dependencies:                                                                            

```pip install -r requirements.txt          ```                                                                  

### 3. Run the application:                                                                            
```python passwordManager.py     ```                                                                       


# Security Features

## Encryption:
Uses AES encryption (via cryptography.Fernet) to secure the vault and logs.                                      
Derives keys using PBKDF2 with SHA256 and a machine-specific pepper.                                      

## Key Management:                                      
Keys are securely stored using the keyring library.                                      

## Session Timeout:
Automatically logs out after 5 minutes of inactivity.       

## HIBP Integration:
Checks passwords against the Have I Been Pwned database for known breaches.

## Clipboard Clearing:
Automatically clears copied passwords from the clipboard after 30 seconds.

# Configuration
The application uses a config.py file to manage settings:

# File Structure
```
passwordManager/                                                                   
├── passwordManager.py       # Main application file                                                                            
├── config.py                # Configuration file                                                                            
├── requirements.txt         # Dependencies                                                                            
├── secure_vault/            # Encrypted vault and salt files                                                                            
├── log_backups/             # Backup logs                                                                            
└── README.md                # Documentation                                                                            
```

# License
This project is licensed under the MIT License. See the LICENSE file for details.

# Author
Developed by @nicola-frattini.
Feel free to reach out for suggestions or contributions!
