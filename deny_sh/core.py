"""
deny-sh - Core encryption engine (Python SDK)

Algorithm-compatible with the TypeScript reference implementation.

Algorithm:

ENCRYPT:
  1. Derive AES-256 key from password1 + password2 via scrypt
  2. Prepend 4-byte plaintext length to plaintext (inside encrypted zone)
  3. XOR (length + plaintext) with control data
  4. AES-256-CTR encrypt the result
  5. Prepend: salt (32 bytes) + IV (16 bytes) as unencrypted header

DECRYPT:
  1. Extract salt + IV from header
  2. Re-derive AES-256 key from passwords + salt
  3. AES-256-CTR decrypt payload
  4. XOR with control data
  5. Read 4-byte length prefix, trim plaintext to that length

DENIABLE DECRYPTION:
  Given ciphertext + passwords + desired fake plaintext:
  1. AES decrypt to get intermediate (= length+plaintext XOR controlData)
  2. Construct fake payload = 4-byte-length(fake) + fake plaintext + random padding
  3. New control data = intermediate XOR fake payload
  4. Now decrypting with new control file produces the fake plaintext
"""

import hashlib
import os
import struct
from Crypto.Cipher import AES

# --- Constants ---

SALT_LENGTH = 32
IV_LENGTH = 16
KEY_LENGTH = 32  # AES-256
HEADER_LENGTH = SALT_LENGTH + IV_LENGTH  # 48 bytes
LENGTH_PREFIX = 4  # 4-byte LE length prefix inside encrypted zone
SCRYPT_N = 2**14  # 16384
SCRYPT_R = 8
SCRYPT_P = 1


# --- Key Derivation ---

def derive_key(password1: str, password2: str, salt: bytes) -> bytes:
    """
    Derive AES-256 key from two passwords using scrypt.
    Combines both passwords via SHA-256 hashing to avoid length ambiguities.
    """
    pw1_hash = hashlib.sha256(password1.encode("utf-8")).digest()
    pw2_hash = hashlib.sha256(password2.encode("utf-8")).digest()
    combined = pw1_hash + pw2_hash

    key = hashlib.scrypt(
        combined,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LENGTH,
    )
    return key


# --- Control Data ---

def generate_control_data(size: int) -> bytes:
    """Generate cryptographically secure random control data."""
    return os.urandom(size)


# --- Internal Helpers ---

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings. Returns bytes of length min(len(a), len(b))."""
    length = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(length))


def _build_payload(data: bytes) -> bytes:
    """Build the inner payload: 4-byte LE length + plaintext data."""
    length_prefix = struct.pack("<I", len(data))
    return length_prefix + data


def _extract_payload(payload: bytes) -> bytes:
    """Extract plaintext from inner payload (4-byte LE length + data)."""
    if len(payload) < LENGTH_PREFIX:
        raise ValueError("Payload too short")

    length = struct.unpack("<I", payload[:LENGTH_PREFIX])[0]

    if length > len(payload) - LENGTH_PREFIX:
        # Length exceeds available data - likely wrong password or control file
        return payload[LENGTH_PREFIX:]

    return payload[LENGTH_PREFIX : LENGTH_PREFIX + length]


# --- Core Encryption ---

def encrypt(
    plaintext: bytes,
    password1: str,
    password2: str,
    control_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using dual passwords and a control file.

    Args:
        plaintext: The data to encrypt.
        password1: First password/passphrase.
        password2: Second password/passphrase.
        control_data: Control file data. If None, random control data is generated.

    Returns:
        Tuple of (ciphertext, control_data).
        ciphertext format: salt(32) + iv(16) + encrypted(length_prefix + plaintext XOR control)

    Raises:
        ValueError: If control_data is too short.
    """
    # Build inner payload with length prefix
    payload = _build_payload(plaintext)

    # Generate control data if not provided
    if control_data is None:
        control_data = generate_control_data(len(payload))

    if len(control_data) < len(payload):
        raise ValueError(
            f"Control data ({len(control_data)} bytes) must be >= "
            f"plaintext + 4 bytes ({len(payload)} bytes)"
        )

    # Generate random salt and IV
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)

    # Derive key
    key = derive_key(password1, password2, salt)

    # XOR payload with control data (the deniability layer)
    control_slice = control_data[: len(payload)]
    xored = _xor_bytes(payload, control_slice)

    # AES-256-CTR encrypt
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    encrypted = cipher.encrypt(xored)

    # Pack: salt || iv || encrypted(length + plaintext XOR controlData)
    result = salt + iv + encrypted

    return (result, control_data)


def decrypt(
    ciphertext: bytes,
    password1: str,
    password2: str,
    control_data: bytes,
) -> bytes:
    """
    Decrypt ciphertext using dual passwords and the original control file.

    Args:
        ciphertext: The encrypted data (salt + iv + encrypted payload).
        password1: First password/passphrase.
        password2: Second password/passphrase.
        control_data: The control file data used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If ciphertext is too short.
    """
    if len(ciphertext) < HEADER_LENGTH:
        raise ValueError("Ciphertext too short - missing header")

    # Extract header
    salt = ciphertext[:SALT_LENGTH]
    iv = ciphertext[SALT_LENGTH:HEADER_LENGTH]
    encrypted_data = ciphertext[HEADER_LENGTH:]

    # Derive key
    key = derive_key(password1, password2, salt)

    # AES-256-CTR decrypt
    decipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    decrypted = decipher.decrypt(encrypted_data)

    # XOR with control data to recover payload
    control_slice = control_data[: len(decrypted)]
    payload = _xor_bytes(decrypted, control_slice)

    # Extract plaintext from payload (reads length prefix, trims)
    plaintext = _extract_payload(payload)

    return plaintext


def generate_deniable_control(
    ciphertext: bytes,
    password1: str,
    password2: str,
    desired_plaintext: bytes,
) -> bytes:
    """
    Generate a new control file that makes existing ciphertext decrypt
    to a completely different plaintext.

    Given:
      - Original ciphertext (encrypted with password1 + password2 + originalControlData)
      - The same passwords
      - A desired fake plaintext

    Returns:
      New control data such that decrypt(ciphertext, passwords, new_control) = desired_plaintext

    Raises:
        ValueError: If ciphertext is too short or desired plaintext is too long.
    """
    if len(ciphertext) < HEADER_LENGTH:
        raise ValueError("Ciphertext too short - missing header")

    # Extract header
    salt = ciphertext[:SALT_LENGTH]
    iv = ciphertext[SALT_LENGTH:HEADER_LENGTH]
    encrypted_data = ciphertext[HEADER_LENGTH:]

    # Build fake payload with length prefix
    fake_payload = _build_payload(desired_plaintext)

    if len(fake_payload) > len(encrypted_data):
        raise ValueError(
            f"Desired plaintext ({len(desired_plaintext)} bytes) is too long "
            f"for this ciphertext"
        )

    # Derive key (same as used for encryption)
    key = derive_key(password1, password2, salt)

    # AES decrypt to get intermediate (= original payload XOR originalControlData)
    decipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    intermediate = decipher.decrypt(encrypted_data)

    # Pad fake payload to match intermediate length with random bytes
    if len(fake_payload) < len(intermediate):
        padding = os.urandom(len(intermediate) - len(fake_payload))
        padded_fake = fake_payload + padding
    else:
        padded_fake = fake_payload

    # New control data = intermediate XOR fakePayload
    new_control_data = _xor_bytes(intermediate, padded_fake)

    return new_control_data
