import os


# PATH FILE NAMES AND DIRECTORIES

SECURE_FOLDER = os.path.join(os.getenv("LOCALAPPDATA", os.path.expanduser("~\\Appdata\\Local")), "PasswordManager")

VAULT_FILE = os.path.join(SECURE_FOLDER,"security","vault.db")

SALT_FILE = os.path.join(SECURE_FOLDER, "security","salt.bin")

LOG_FILE = os.path.join(SECURE_FOLDER, "logs","app.log")

USERNAME_FILE = os.path.join(SECURE_FOLDER, "security", "username.enc")

LOG_BACKUP_FOLDER = os.path.join(SECURE_FOLDER, "logs","backup")

FILE_2FA = os.path.join(SECURE_FOLDER, "security", "2fa.enc")


#  ServiceS name for keyring
SERVICE_NAME = "PasswordManager"


# Timeout for the session in seconds
SESSION_TIMEOUT = 300  # seconds

# Maximum size of the log file in bytes
LOG_MAX_SIZE = 5 * 1024 * 1024  # 5 MB

BACKUP_RETENTION_DAYS = 30

# Default password length for generated passwords
PASSWORD_LENGTH_DEFAULT = 16

# PBKDF2 Iterations
PBKDF2_ITERATIONS = 1_000_000