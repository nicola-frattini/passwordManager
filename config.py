import os


# PATH FILE NAMES AND DIRECTORIES

SECURE_FOLDER = "secure_vault"

VAULT_FILE = os.path.join(SECURE_FOLDER, "vault.enc")

SALT_FILE = os.path.join(SECURE_FOLDER, "salt.bin")

LOG_FILE = "password_manager.log"

LOG_BACKUP_FOLDER = "log_backups"


#  Service name for keyring
SERVICE_NAME = "PasswordManager"

# Timeout for the session in seconds
SESSION_TIMEOUT = 300  # seconds

# Maximum size of the log file in bytes
LOG_MAX_SIZE = 5 * 1024 * 1024  # 5 MB

# Default password length for generated passwords
PASSWORD_LENGTH_DEFAULT = 16