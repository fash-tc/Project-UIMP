"""Symmetric encryption for is_secret=1 config values and zabbix poller_pass.

Key derivation: HKDF-SHA256 over AUTH_SECRET with a build-constant salt.
Encryption: Fernet (AES-128-CBC + HMAC-SHA256 with random IV per record).

WARNING: rotating AUTH_SECRET will brick every encrypted row. See spec §10.
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Build-constant salt. Rotating this == rotating master key. Do not change
# without a planned migration. 32 bytes.
_HKDF_SALT = bytes.fromhex(
    "9c1f0c8d4b21e3a6f54b7c2d8e9a05f1"
    "23456789abcdef0123456789abcdef01"
)
_HKDF_INFO = b"admin-api-secrets-v1"


def derive_fernet_key(master_secret: str) -> bytes:
    """Return a base64url-encoded 32-byte key suitable for Fernet."""
    if not master_secret:
        raise ValueError("master_secret must be non-empty")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    key = hkdf.derive(master_secret.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


class SecretBox:
    """Lightweight wrapper around Fernet so callers don't see crypto primitives."""

    def __init__(self, master_secret: str | None = None) -> None:
        secret = master_secret if master_secret is not None else os.environ["AUTH_SECRET"]
        self._fernet = Fernet(derive_fernet_key(secret))

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        return self._fernet.encrypt(bytes(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)

    def encrypt_str(self, plaintext: str) -> bytes:
        return self.encrypt(plaintext.encode("utf-8"))

    def decrypt_str(self, ciphertext: bytes) -> str:
        return self.decrypt(ciphertext).decode("utf-8")
