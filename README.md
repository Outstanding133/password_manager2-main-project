CIPHER - Password Vault

A lightweight, local-first password manager built with Python, Flask, SQLite and Fernet encryption.

CIPHER is designed to store and manage credentials locally, with a focus on privacy, security and low resource consumption.

1. Features

Master password authentication.

Encrypted credential storage using Fernet.

SQLite database for local data storage.

Server-side vault encryption key storage.

CSRF protection for state-changing API requests.

Login rate limiting to help prevent brute-force attacks.

Automatic master password rotation after successful unlock.

Password strength analysis.

Credential management through a web dashboard.

Local operation without cloud storage.

2. Technology Stack

Technology

Purpose

Python

Backend programming

Flask

Web application and API

SQLite

Local database

Cryptography (Fernet)

Credential encryption

HTML, CSS, JavaScript

Frontend

PBKDF2-HMAC-SHA256

Key derivation

3. Project Structure

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

Important: vault.db contains your saved vault data. Never delete or replace it when updating the application.

4. Requirements

Windows 10 or Windows 11

Python 3.14 (or a compatible Python version)

pip

A modern web browser

VS Code (recommended)

5. Installation

Step 1: Open the project

Open the project folder in VS Code.

Open the integrated terminal:

Ctrl + `

Step 2: Install dependencies

Run:

py -m pip install -r requirements.txt

Wait until all required packages are installed.

Step 3: Start CIPHER

Run:

py app.py

Step 4: Open the application

Open your browser and visit:

http://127.0.0.1:5000

CIPHER should now be accessible through your local browser.
