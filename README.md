# snowcap-tcrypt

Python decrypt support for the Snowcap Suitcase encryption format. Decrypt-only by design — encryption is handled by [tcrypt-pack](https://github.com/RickAtSnowcap/tcrypt-pack).

## What it does

Decrypts AES-256-GCM encrypted values produced by the Snowcap TCrypt ecosystem. Used by Python ETL jobs and database pollers that need to read encrypted config values at runtime.

**Wire format:** `Base64(nonce[12] + ciphertext[n] + tag[16])`

Cross-language compatible with [tcrypt-lib](https://github.com/RickAtSnowcap/tcrypt-lib) (.NET). Values encrypted in C# decrypt correctly in Python and vice versa.

## API

```python
from snowcap_tcrypt import load_key, decrypt

# Load key from systemd credential (production)
key = load_key()

# Or bring your own 32-byte key (development/testing)
key = base64.b64decode("your-base64-key-here")

# Decrypt
plaintext = decrypt(encrypted_value, key)
```

### `load_key(credential_name="suitcase-key") -> bytes`

Reads the 32-byte AES key from systemd's credential directory (`$CREDENTIALS_DIRECTORY`). The key is TPM-sealed and delivered to the process at service start via `LoadCredentialEncrypted=` in the unit file.

### `decrypt(encrypted_text: str, key: bytes) -> str`

Decrypts a Base64-encoded Suitcase value. Returns the plaintext string. Raises `InvalidTag` if the key is wrong or the data has been tampered with.

## Install

```bash
pip install /path/to/tcrypt-py
```

Or for development:

```bash
pip install -e /path/to/tcrypt-py
```

## Requirements

- Python >= 3.10
- `cryptography` package
- For `load_key()`: Linux with systemd and TPM 2.0

## License

MIT
