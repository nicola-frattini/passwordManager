# Password Manager

A secure, terminal-based password manager written in Python. Built with strong cryptographic foundations, it stores all credentials in an encrypted local vault protected by a master password, Argon2id key derivation, AES-256-CBC encryption, HMAC-SHA256 integrity verification, and TOTP-based two-factor authentication.

> Made by [@nicola-frattini](https://github.com/nicola-frattini)

---

## Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [First Run](#first-run)
- [Usage](#usage)
- [Vault Storage & Integrity](#vault-storage--integrity)
- [Logging](#logging)
- [Known Limitations & Issues](#known-limitations--issues)
- [Disclaimer](#disclaimer)

---

## Features

- **AES-256-CBC encryption** for all stored fields (site, username, password, URL, notes)
- **Argon2id key derivation** with machine-specific pepper for strong brute-force resistance
- **HMAC-SHA256 integrity check** on the vault file to detect any tampering or corruption
- **TOTP-based 2FA**, verified before vault decryption, compatible with Google Authenticator, Authy, and any TOTP app
- **Encrypted log files**, every log entry is individually AES-256-CBC encrypted
- **In-memory SQLite vault**, the decrypted database lives only in RAM during the session; it never touches disk in plaintext
- **Clipboard auto-clear**, copied passwords are wiped from the clipboard after 30 seconds
- **Session timeout**, auto-exits after 5 minutes of inactivity
- **Password breach check** via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) using the k-anonymity model (only the first 5 characters of the SHA-1 hash are sent)
- **Secure password generator** using Python's `secrets` module, with configurable length and special characters
- **Auto-login**, opens the website and types credentials automatically (see limitations)
- **Vault export/import** with paired HMAC file for integrity-preserving backups
- **Key export** for offline recovery
- **Encrypted log export**, decrypts and writes logs to a plaintext file on demand

---

## Security Architecture

### Key Derivation

The master password is never stored anywhere. On each login it is concatenated with a **machine-specific pepper**, then fed into **Argon2id** alongside the decrypted salt:

| Parameter     | Value        |
|---------------|--------------|
| Algorithm     | Argon2id     |
| Time cost     | 3 iterations |
| Memory cost   | 64 MB        |
| Parallelism   | 2 threads    |
| Output length | 32 bytes     |

The same `derive_key()` function is called with different inputs to produce distinct keys:

| Key | Input |
|-----|-------|
| Vault key | `master_password + pepper`, `salt` |
| Salt encryption key | `master_password + pepper`, `salt` (cached in OS keyring) |
| Log key | `(master_password + "LOGS") + pepper`, `salt` |
| 2FA encryption key | `master_password + pepper`, `salt` |

### Encryption

All sensitive data (credentials, salt file, 2FA secret, individual log entries) is encrypted with **AES-256-CBC**. A fresh random 16-byte IV is generated for every encryption call and prepended to the ciphertext. PKCS7 padding is applied before encryption.

**Ciphertext layout:**
```
[ IV (16 bytes) ][ Ciphertext (N bytes, multiple of 16) ]
```

### Integrity

Every time the vault is saved, an **HMAC-SHA256** of the full encrypted blob is computed using the vault key and written to `hmacVault.hmac`. On the next login, the HMAC is recomputed and compared using `hmac.compare_digest()` (constant-time) before any decryption is attempted. A mismatch blocks access entirely.

### Salt & Pepper

**Salt** (16 random bytes): generated once on first run with `os.urandom(16)`, immediately encrypted with the salt key, and stored in `salt.bin`. It is decrypted at login and kept in memory for the duration of the session.

**Pepper**: on first run, the machine's MAC address (`uuid.getnode()`) and hostname are concatenated and SHA-256 hashed to produce a 64-character hex string. This value is saved to `pepper.bin` with owner-only permissions (`chmod 600`) and **read from file on every subsequent run**, it is never regenerated unless the file is missing. This ties the vault cryptographically to the machine it was created on.

### 2FA (TOTP)

A random base32 TOTP secret is generated with `pyotp.random_base32()` on first run and shown as a QR code for one-time enrollment. The secret is then AES-encrypted with the vault key and stored in `2fa.enc`. On every login, the TOTP code is verified **before** any salt decryption or vault access. Three consecutive failed attempts cause the program to exit.

### In-Memory Vault

The SQLite database is decrypted into a `sqlite3.connect(":memory:")` connection. All reads and writes during the session happen entirely in RAM. On clean exit (and on `KeyboardInterrupt`), the database is serialized via `conn.backup()`, AES-encrypted, written to `vault.db`, and a new HMAC is computed and saved.

---

## Project Structure

```
PasswordManager/
│
├── passwordManager.py              # Entry point - login flow, main menu loop, vault save on exit
│
└── src/
    ├── Cryptography/
    │   ├── encryption.py           # AES-256-CBC encrypt (random IV + ciphertext)
    │   ├── decryption.py           # AES-256-CBC decrypt with PKCS7 unpadding
    │   ├── keyDerivation.py        # Argon2id derive_key(), pepper management, keyring helpers
    │   ├── keyringCheck.py         # Keyring consistency check and auto-fix
    │   ├── saltManagement.py       # Salt file encrypt/decrypt
    │   └── hmacManagement.py       # HMAC-SHA256 compute, save, load
    │
    ├── Files/
    │   ├── vaultManagement.py      # Vault init, DB encrypt/decrypt, HMAC integrity check
    │   ├── folderManagement.py     # Secure folder creation, Windows hidden attribute, file chmod
    │   ├── exports.py              # Key export, log export, vault + HMAC export
    │   └── imports.py              # Vault import with automatic backup of current vault
    │
    ├── GUI/
    │   ├── GUIFunctions.py         # ASCII title banner, clear screen
    │   └── menus.py                # All interactive menus (manage entries, logs, advanced options)
    │
    ├── Log/
    │   ├── logging.py              # Logging setup, log display/search/export, daily backup
    │   └── EncryptedLogHandler.py  # Custom logging.Handler that AES-encrypts each record
    │
    └── Utils/
        ├── config.py               # All file paths and global constants
        ├── inputs.py               # get_valid_input() helper with whitelist validation
        ├── session.py              # Session timeout enforcement, login event logging
        ├── twoFA.py                # TOTP setup (QR code display) and verification
        ├── entriesManagement.py    # Add, view, edit, delete entries; clipboard copy; auto-login
        └── passwordManagement.py  # Password generator (secrets module), HIBP breach checker
```

---

## Requirements

- **Python 3.10+**
- **Windows**, the data folder uses `%LOCALAPPDATA%` and folder hiding uses the Windows API via `ctypes`. Linux and macOS are not officially supported.

### Python Dependencies

```
argon2-cffi
colorama
cryptography
keyring
pyotp
qrcode[pil]
pyperclip
pyautogui
requests
tqdm
```

Install everything at once:

```bash
pip install argon2-cffi colorama cryptography keyring pyotp "qrcode[pil]" pyperclip pyautogui requests tqdm
```

Or with a `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/nicola-frattini/password-manager.git
cd password-manager
pip install -r requirements.txt
```

---

## First Run

On the first launch the setup wizard will guide you through three steps:

1. **Choose a username**, used only for display in the UI, not a secret.
2. **Set and confirm a master password**, the only secret you need to remember. It is never stored.
3. **Enroll your authenticator app**, a QR code is printed in the terminal. Scan it with Google Authenticator, Authy, or any TOTP-compatible app. You can also manually enter the displayed base32 key.

> **The TOTP secret is shown exactly once.** If you lose access to your authenticator and have no backup of the base32 secret, you will be permanently locked out of your vault.

After setup, the following files are created under `%LOCALAPPDATA%\PasswordManager\`:

```
PasswordManager\
├── security\
│   ├── vault.db          # AES-256-CBC encrypted SQLite vault
│   ├── salt.bin          # AES-256-CBC encrypted salt (16 bytes)
│   ├── 2fa.enc           # AES-256-CBC encrypted TOTP secret
│   ├── hmacVault.hmac    # HMAC-SHA256 of the encrypted vault
│   ├── pepper.bin        # Machine-bound pepper (hex string, chmod 600)
│   └── username.enc      # Display username (stored in plaintext despite the extension)
└── logs\
    ├── app.log           # AES-encrypted log file
    └── backup\           # Daily log backups, auto-purged after 30 days
```

---

## Usage

```bash
python passwordManager.py
```

On each launch you will be prompted for your master password, then your TOTP code. Once authenticated, the vault decrypts into RAM and the main menu appears.

### Main Menu

```
[1] Add a new account
[2] Manage accounts
[3] Advanced options
[0] Exit
```

### Manage Accounts

| Option | Description |
|--------|-------------|
| View all | Lists all entries; passwords are masked as `**********` |
| Copy a password | Copies the plaintext password to clipboard; auto-cleared after 30 seconds |
| Edit an account | Update username, URL, password (manual or generated), or notes |
| Delete an account | Permanently removes an entry after explicit confirmation |
| Auto-login | Opens the URL in the default browser and types credentials via `pyautogui` (⚠️ see below) |
| Check passwords integrity | Checks every stored password against HaveIBeenPwned and reports any breached ones |

### Advanced Options

| Option | Description |
|--------|-------------|
| Export keys | Writes derived and keyring-cached keys to a text file for backup |
| View log menu | View all logs, filter by date/level/keyword, or export decrypted logs to a file |
| Export crypted vault backup | Copies the encrypted `vault.db` and `hmacVault.hmac` to a user-specified path |
| Import crypted vault backup | Replaces the vault with an imported file; backs up the current vault to `vault.db.bak` first |

### Password Generator

When adding or editing an entry you can generate a password. The generator uses Python's `secrets` module (cryptographically secure PRNG):

- Character set: `a-z A-Z 0-9` and optionally `@#!+=_-`
- Minimum length: 8 characters
- Default length: 16 characters (can be overridden per session)

---

## Vault Storage & Integrity

At the end of every session (normal exit or `KeyboardInterrupt`) the following sequence runs:

1. The in-memory SQLite database is serialized to a temporary file via `conn.backup()`.
2. The raw bytes are read and the temp file is deleted.
3. The bytes are AES-256-CBC encrypted with the vault key.
4. The encrypted blob is written to `vault.db`.
5. An HMAC-SHA256 of the blob is computed and written to `hmacVault.hmac`.

On the next login, the HMAC is recomputed and verified with `hmac.compare_digest()` before any decryption. If the check fails (wrong key, tampered file, or corruption), the program refuses to open the vault and logs the event.

---

## Logging

Every log entry (login events, add/edit/delete actions, errors, warnings) is **individually AES-256-CBC encrypted** using the log key before being appended to `app.log`. Logs are never written in plaintext. The plaintext format before encryption is:

```
YYYY-MM-DD HH:MM:SS,mmm - LEVEL - message
```

**Viewing logs:** Advanced Options → View log menu. Options include viewing all entries, filtering by date / log level / keyword, and exporting decrypted content to a file.

**Backups:** A copy of the encrypted log file is saved daily to `logs\backup\` with a `YYYY-MM-DD` filename. Backups older than 30 days are automatically deleted.

---

## Known Limitations & Issues

**Windows only**
The secure folder path relies on `%LOCALAPPDATA%` and folder hiding uses `ctypes.windll`. The program will run on Linux/macOS only with code changes to these platform-specific parts.

**Auto-login is inherently risky**
Auto-login uses `pyautogui.typewrite()` to simulate keyboard input into the active window. It is vulnerable to keyloggers, focus-stealing by other windows during the 3-second delay, and mis-typed characters for passwords containing non-ASCII characters. Use it at your own risk and only in a trusted environment.

**Vault is machine-bound**
Because the pepper is derived from the machine's MAC address and hostname, a vault cannot be opened on a different machine without first exporting the `pepper.bin` file along with the vault backup.

**No password history**
Editing a password permanently overwrites the previous value with no recovery option.

**Keyring dependency**
Derived keys are cached in the OS keyring after first login to avoid re-running Argon2id on every operation. If the keyring becomes inconsistent (e.g. after reinstalling the app or changing the master password externally), `keyringCheck.py` provides an auto-fix routine that clears and regenerates the cached keys.

**Minor bug,  HIBP return type**
In `passwordManagement.py`, `check_password_hibp()` returns `{count}` (a Python `set` literal) instead of `int(count)` when a breach is found. The breach detection itself works correctly (a non-empty set is truthy), but the exact breach count is not reported accurately in the log warning.

---

## Disclaimer

This project was built for educational purposes and personal use. While it follows established cryptographic practices, it has **not been audited** by a third party. Use it at your own risk. The author is not responsible for any data loss or security issues resulting from the use of this software.

---

*Made with by [@nicola-frattini]*
