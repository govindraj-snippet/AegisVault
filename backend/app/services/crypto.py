import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# AES-GCM constants
_KEY_BYTES = 32   # 256-bit key
_NONCE_BYTES = 12  # 96-bit nonce — NIST recommended for GCM


def encrypt_file(raw_bytes: bytes) -> tuple[bytes, str]:
    """
    Encrypts arbitrary bytes using AES-256-GCM.

    Strategy:
      - A fresh 256-bit key is generated per file — never reused.
      - A fresh 96-bit nonce is generated per encryption call.
      - The nonce is prepended to the ciphertext so decrypt_file
        is self-contained: [ nonce (12 B) | ciphertext+tag ]
      - The GCM authentication tag (16 B) is appended automatically
        by the `cryptography` library inside the ciphertext blob.

    Returns:
        ciphertext : nonce + encrypted bytes + GCM tag, as raw bytes
        key_b64    : URL-safe base64-encoded 256-bit key (store this in DB)
    """
    key: bytes = os.urandom(_KEY_BYTES)
    nonce: bytes = os.urandom(_NONCE_BYTES)

    aesgcm = AESGCM(key)
    encrypted: bytes = aesgcm.encrypt(nonce, raw_bytes, associated_data=None)

    # Layout: | 12-byte nonce | ciphertext | 16-byte GCM tag |
    ciphertext: bytes = nonce + encrypted

    key_b64: str = base64.urlsafe_b64encode(key).decode("utf-8")
    return ciphertext, key_b64


def decrypt_file(ciphertext: bytes, key_b64: str) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext produced by encrypt_file().

    Raises:
        ValueError  : if the ciphertext is too short to contain a valid nonce.
        InvalidTag  : if the key is wrong, or the ciphertext has been tampered
                      with. This is an explicit fail-closed security boundary —
                      we never return partial or unauthenticated plaintext.
    """
    if len(ciphertext) <= _NONCE_BYTES:
        raise ValueError(
            f"Ciphertext too short: expected > {_NONCE_BYTES} bytes, "
            f"got {len(ciphertext)}."
        )

    key: bytes = base64.urlsafe_b64decode(key_b64.encode("utf-8"))
    nonce: bytes = ciphertext[:_NONCE_BYTES]
    encrypted: bytes = ciphertext[_NONCE_BYTES:]

    aesgcm = AESGCM(key)

    try:
        plaintext: bytes = aesgcm.decrypt(nonce, encrypted, associated_data=None)
    except InvalidTag as exc:
        # Never surface partial data. Force caller to treat this as fatal.
        raise InvalidTag(
            "Decryption failed: authentication tag mismatch. "
            "The key is incorrect or the ciphertext has been tampered with."
        ) from exc

    return plaintext