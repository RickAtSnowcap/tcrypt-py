"""
Snowcap TCrypt — Python decrypt support for the Suitcase encryption format.

Format: Base64(nonce[12] + ciphertext[n] + tag[16])
  - AES-256-GCM authenticated encryption (AEAD)
  - 12-byte random nonce, 16-byte authentication tag

Designed for ETL jobs and Python utilities in the Credentialing project
that need to read encrypted Suitcase config values. Encryption is handled
by tcrypt-pack (.NET AOT CLI) — this module only decrypts.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_KEY_LENGTH = 32


def load_key(credential_name: str = "suitcase-key") -> bytes:
    """Load the Suitcase key from the systemd credential directory.

    The key is delivered by systemd via LoadCredentialEncrypted= after
    TPM unsealing at service start.

    Args:
        credential_name: Name of the credential (default: "suitcase-key").

    Returns:
        The 32-byte AES-256 key.

    Raises:
        RuntimeError: If CREDENTIALS_DIRECTORY is not set.
        FileNotFoundError: If the credential file does not exist.
        ValueError: If the key is not exactly 32 bytes.
    """
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        raise RuntimeError(
            "CREDENTIALS_DIRECTORY is not set. This application must run as a "
            "systemd service with LoadCredentialEncrypted= configured."
        )

    key_path = os.path.join(cred_dir, credential_name)
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Credential '{credential_name}' not found at {key_path}. "
            "Verify LoadCredentialEncrypted= is configured in the unit file."
        )

    key = open(key_path, "rb").read()
    if len(key) != _KEY_LENGTH:
        raise ValueError(
            f"Key must be exactly {_KEY_LENGTH} bytes for AES-256, got {len(key)}."
        )
    return key


def decrypt(encrypted_text: str, key: bytes) -> str:
    """Decrypt a Suitcase-encrypted value.

    Args:
        encrypted_text: Base64-encoded string containing nonce + ciphertext + tag.
        key: The 32-byte AES-256 key.

    Returns:
        The decrypted plaintext string.

    Raises:
        ValueError: If the key length is wrong or data is too short.
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key, tampered data).
    """
    if len(key) != _KEY_LENGTH:
        raise ValueError(
            f"Key must be exactly {_KEY_LENGTH} bytes for AES-256, got {len(key)}."
        )

    raw = base64.b64decode(encrypted_text)
    if len(raw) < _NONCE_LENGTH + _TAG_LENGTH:
        raise ValueError("Encrypted data is too short to contain a nonce and tag.")

    nonce = raw[:_NONCE_LENGTH]
    # GCM: AESGCM.decrypt expects nonce + (ciphertext || tag) concatenated
    ciphertext_and_tag = raw[_NONCE_LENGTH:]

    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext_and_tag, None)

    return plaintext.decode("utf-8")
