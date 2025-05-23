#  Python Password Manager

A local, secure, and encrypted password manager built with Python. Designed with security, simplicity, and privacy in mind — no cloud, no external storage, everything stays on your machine.

##  Features

- AES-256 encryption in CBC mode with PKCS7 padding
- Vault integrity verification using HMAC SHA-256
- Encrypted SQLite database stored locally
- Secure folders and hidden files for Windows
- Master password secured via Argon2id key derivation (with PEPPER)
- TOTP-based two-factor authentication (QR code setup)
- Auto-login via PyAutoGUI (vulnerable to keyloggers, optional)
- Check passwords against known breaches using the Have I Been Pwned API
- Encrypted and color-coded logs with advanced filtering/search/export
- Clipboard-safe password handling (auto-clears after 30 seconds)
- Key backup and export functionality

##  Project Structure

```
.
├── passwordManager.py     # Main script with all the functionality
├── config.py              # Configuration constants and paths
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/password-manager.git
cd password-manager
```

### 2. Create virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## ▶️ Usage

Simply run:

```bash
python passwordManager.py
```

### First-time setup

- You'll be prompted to create a master password and username.
- A secure salt file and encrypted vault will be initialized.
- 2FA setup with TOTP and QR code.
- Vault is stored locally and encrypted end-to-end.

### Regular usage

- Enter your master password and TOTP code to access your vault.
- Add, edit, delete, export, and auto-fill credentials.
- Export logs and keys when needed.

##  Security Design

- **Encryption**: AES-256-CBC with random IVs, passwords are encrypted at rest.
- **Key Derivation**: Argon2id with machine-specific PEPPER.
- **Integrity**: HMAC-SHA256 checks to detect tampering.
- **2FA**: Enforced TOTP for login verification.
- **Clipboard**: Passwords copied are auto-cleared after 30s.

##  Online Security

- Passwords are never stored in plaintext.
- Uses the HaveIBeenPwned API (range query via SHA1 prefix) to check if a password has been leaked.

## ⚙️ Dependencies

All are pinned in `requirements.txt`:

- `cryptography`
- `argon2-cffi`
- `keyring`
- `pyotp`
- `qrcode`
- `pyautogui`
- `pyperclip`
- `colorama`
- `tqdm`
- `requests`

## 📤 Export/Import

- Encrypted vault and keys can be exported and re-imported manually.
- Automatic log backup system (rotated, retention policy applied).

## ⚠️ Disclaimer

This is a personal security tool. Use at your own risk. Always back up your encrypted vault and keys. No cloud, no recovery service. You lose your master password = you lose access.

## 📄 License

MIT License — feel free to use, modify, and contribute.

---

Made by @nicola-frattini.