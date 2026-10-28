"""
aes_cipher.py
-------------
Core encryption / decryption logic for the Secure Text Encryption and
Decryption System.

Algorithm details
- Cipher         : AES-256 in GCM mode (Galois/Counter Mode)
- Key derivation : PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte random salt
- Nonce (IV)     : 12 random bytes, new for every message
- Integrity      : GCM's 16-byte authentication tag detects any tampering
                   or a wrong password

Output format (Base64 encoded so it can be copied, emailed or stored as text):

    | salt (16 bytes) | nonce (12 bytes) | ciphertext + tag (n + 16 bytes) |
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16          # bytes
NONCE_SIZE = 12         # bytes (recommended size for GCM)
KEY_SIZE = 32           # bytes -> AES-256
TAG_SIZE = 16           # bytes, appended to the ciphertext by AESGCM
ITERATIONS = 200_000    # PBKDF2 work factor


class DecryptionError(Exception):
    """Raised when a message cannot be decrypted (wrong password or tampered data)."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password into a 256-bit AES key using PBKDF2."""
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: str, password: str) -> str:
    """Encrypt a text message and return a Base64 string."""
    if plaintext is None:
        raise ValueError("Message must not be None.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ciphertext).decode("ascii")


def decrypt(token: str, password: str) -> str:
    """Decrypt a Base64 string produced by encrypt() and return the original text."""
    try:
        data = base64.b64decode(token.strip(), validate=True)
    except (ValueError, TypeError) as exc:
        raise DecryptionError("Input is not valid encrypted data (bad Base64).") from exc

    if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Input is too short to be valid encrypted data.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError("Wrong password or the message has been tampered with.") from exc

    return plaintext.decode("utf-8")
