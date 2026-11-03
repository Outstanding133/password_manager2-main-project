"""
Encryption Engine for Secure Password Manager
Uses PBKDF2HMAC for key derivation and Fernet (AES-128-CBC) for encryption.
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte random salt."""
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible key from the master password using PBKDF2HMAC.

    Args:
        master_password: The user's master password in plaintext.
        salt: A unique 16-byte salt stored alongside the vault.

    Returns:
        A 32-byte URL-safe base64-encoded key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,          # OWASP 2023 recommendation
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def hash_key(key: bytes) -> str:
    """
    Create a SHA-256 hex digest of the derived key.
    Used to verify the master password without storing it.
    """
    return hashlib.sha256(key).hexdigest()


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt_data(plaintext: str, key: bytes) -> str:
    """
    Encrypt a plaintext string using Fernet.

    Args:
        plaintext: The string to encrypt.
        key: A Fernet-compatible key (from derive_key).

    Returns:
        The ciphertext as a UTF-8 string.
    """
    cipher = Fernet(key)
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str, key: bytes) -> str:
    """
    Decrypt a ciphertext string using Fernet.

    Args:
        ciphertext: The encrypted string.
        key: The same Fernet key used for encryption.

    Returns:
        The original plaintext string.

    Raises:
        InvalidToken: If the key is wrong or the data has been tampered with.
    """
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext.encode()).decode()
