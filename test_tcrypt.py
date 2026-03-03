"""Tests for snowcap_tcrypt — decrypt support for Suitcase encryption format (AES-256-GCM)."""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from snowcap_tcrypt import decrypt, load_key

passed = 0
failed = 0


def assert_test(condition: bool, name: str):
    global passed, failed
    if condition:
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name}")
        failed += 1


def make_test_encrypted(plaintext: str, key: bytes) -> str:
    """Encrypt a value using the same format as SuitcaseCrypt.Encrypt (for testing)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets

    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag concatenated
    ct_and_tag = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct_and_tag).decode("ascii")


print("=== snowcap_tcrypt Tests (AES-256-GCM) ===")
print()

key = os.urandom(32)

# Test 1: Basic roundtrip
print("1. Basic decrypt roundtrip")
original = "Server=db.local;Database=test;Password=Secret123!"
enc = make_test_encrypted(original, key)
dec = decrypt(enc, key)
assert_test(dec == original, "Decrypted matches original")

# Test 2: Per-value random nonce produces different ciphertext
print("2. Per-value random nonce")
enc2 = make_test_encrypted(original, key)
assert_test(enc != enc2, "Same plaintext produces different ciphertext")
assert_test(decrypt(enc2, key) == original, "Both decrypt to same value")

# Test 3: Empty string
print("3. Empty string")
enc_empty = make_test_encrypted("", key)
assert_test(decrypt(enc_empty, key) == "", "Empty string roundtrip")

# Test 4: Unicode
print("4. Unicode")
unicode_str = "Héllo Wörld! 日本語テスト"
enc_uni = make_test_encrypted(unicode_str, key)
assert_test(decrypt(enc_uni, key) == unicode_str, "Unicode roundtrip")

# Test 5: Long string
print("5. Long string")
long_str = "A" * 10000
enc_long = make_test_encrypted(long_str, key)
assert_test(decrypt(enc_long, key) == long_str, "10K character roundtrip")

# Test 6: Wrong key (GCM auth tag rejects)
print("6. Wrong key")
wrong_key = os.urandom(32)
try:
    decrypt(enc, wrong_key)
    assert_test(False, "Wrong key should raise")
except Exception:
    assert_test(True, "Wrong key raises exception")

# Test 7: Invalid key length
print("7. Invalid key length")
try:
    decrypt(enc, os.urandom(16))
    assert_test(False, "16-byte key should raise")
except ValueError:
    assert_test(True, "16-byte key raises ValueError")

# Test 8: Corrupted data
print("8. Corrupted data")
try:
    decrypt("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key)
    assert_test(False, "Corrupted data should raise")
except Exception:
    assert_test(True, "Corrupted data raises exception")

# Test 9: Tampered ciphertext — flip a byte (GCM detects)
print("9. Tampered ciphertext detected")
tampered = bytearray(base64.b64decode(enc))
tampered[14] ^= 0xFF
try:
    decrypt(base64.b64encode(bytes(tampered)).decode("ascii"), key)
    assert_test(False, "Tampered ciphertext should raise")
except Exception:
    assert_test(True, "Tampered ciphertext raises exception")

# Test 10: load_key without CREDENTIALS_DIRECTORY
print("10. load_key without CREDENTIALS_DIRECTORY")
os.environ.pop("CREDENTIALS_DIRECTORY", None)
try:
    load_key()
    assert_test(False, "Missing CREDENTIALS_DIRECTORY should raise")
except RuntimeError:
    assert_test(True, "Missing CREDENTIALS_DIRECTORY raises RuntimeError")

# Test 11: load_key with missing file
print("11. load_key with missing credential file")
os.environ["CREDENTIALS_DIRECTORY"] = "/tmp/nonexistent-cred-dir"
try:
    load_key()
    assert_test(False, "Missing credential file should raise")
except FileNotFoundError:
    assert_test(True, "Missing credential file raises FileNotFoundError")
finally:
    os.environ.pop("CREDENTIALS_DIRECTORY", None)

print()
print(f"=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
