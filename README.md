# CIPHER - Password Vault

A lightweight, local-first password manager built with Python, Flask, SQLite and Fernet encryption.

CIPHER is designed to store and manage credentials locally, with a focus on privacy, security and low resource consumption.

## 1. Features

- Master password authentication.
- Encrypted credential storage using Fernet.
- SQLite database for local data storage.
- Server-side vault encryption key storage.
- CSRF protection for state-changing API requests.
- Login rate limiting to help prevent brute-force attacks.
- Automatic master password rotation after successful unlock.
- Password strength analysis.
- Credential management through a web dashboard.
- Local operation without cloud storage.

## 2. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application and API |
| SQLite | Local database |
| Cryptography (Fernet) | Credential encryption |
| HTML, CSS, JavaScript | Frontend |
| PBKDF2-HMAC-SHA256 | Key derivation |

## 3. Project Structure

```text
CIPHER/
│
├── app.py
├── database.py
├── encryption.py
├── password_utils.py
├── requirements.txt
├── vault.db
│
├── static/
│   ├── app.js
│   └── style.css
│
└── templates/
    └── index.html
```

**Important:** `vault.db` contains your saved vault data. Never delete or replace it when updating the application.

## 4. Requirements

- Windows 10 or Windows 11
- Python 3.14 (or a compatible Python version)
- pip
- A modern web browser
- VS Code (recommended)

## 5. Installation

### Step 1: Open the project

Open the project folder in VS Code.

Open the integrated terminal:

```powershell
Ctrl + `
```

### Step 2: Install dependencies

Run:

```powershell
py -m pip install -r requirements.txt
```

Wait until all required packages are installed.

### Step 3: Start CIPHER

Run:

```powershell
py app.py
```

### Step 4: Open the application

Open your browser and visit:

```text
http://127.0.0.1:5000
```

CIPHER should now be accessible through your local browser.

## 6. First-Time Setup

1. Open CIPHER in your browser.
2. Create your master password.
3. Confirm your master password.
4. Access the dashboard.
5. Start adding your credentials.

**Important:** Remember your master password and follow the application's password rotation instructions.

CIPHER automatically generates a new master password after successful unlock. Copy or download the generated password and confirm it before proceeding. You will need it for your next unlock.

Losing the generated master password can result in permanent loss of access to your encrypted vault.

## 7. Running CIPHER Again

Whenever you want to use CIPHER:

1. Open the project folder.
2. Open PowerShell or the VS Code terminal.
3. Run:

```powershell
py app.py
```

4. Visit:

```text
http://127.0.0.1:5000
```

5. Unlock your vault.

To stop the application, press:

```text
Ctrl + C
```

## 8. Offline Usage

CIPHER is designed to operate locally.

After installing the Python dependencies, you can disconnect from the internet and run the application.

The following components work locally:

- Flask backend
- SQLite database
- Fernet encryption
- Authentication
- Credential management
- Web dashboard

No cloud account or remote database is required.

Note: External websites still require an internet connection when you want to log in to them.

## 9. Database and Backup

CIPHER uses SQLite to store vault information.

The database file is:

```text
vault.db
```

Keep a secure backup of this file.

Also maintain a secure backup of your master password and any newly generated rotated password.

For a consistent backup, stop CIPHER before copying the database file.

Never share your database or master password publicly.

## 10. Security Notes

- Do not share your master password.
- Do not expose the local Flask service to public networks.
- Do not use real credentials while security testing is incomplete.
- Keep Python dependencies updated.
- Maintain secure backups.
- Use the application only on a trusted device.

The current server-side encryption key storage uses process memory. Restarting Flask clears active unlock sessions, so you will need to unlock the vault again.

## 11. Future Development

Planned improvements:

- Browser extension for Chrome and Microsoft Edge.
- Website recognition and credential matching.
- Secure username and password autofill.
- Improved local service authentication.
- Further security hardening.
- Memory and performance optimization.
- Improved backup and recovery workflow.

## 12. Project Goal

The long-term goal of CIPHER is to create a lightweight, privacy-focused password manager that operates locally, minimizes unnecessary resource consumption and provides convenient browser integration without depending on cloud-based password storage.

---

**CIPHER - Your Passwords. Your Device. Your Control.**
