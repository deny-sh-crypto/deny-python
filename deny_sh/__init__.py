"""
deny-sh — Deniable encryption for Python.

Same algorithm as the TypeScript reference implementation.
Ciphertext format is byte-for-byte compatible across SDKs.

Usage:
    from deny_sh import encrypt, decrypt, generate_deniable_control, generate_control_data

    # Encrypt
    ciphertext, control = encrypt(b"secret message", "pw1", "pw2")

    # Decrypt
    message = decrypt(ciphertext, "pw1", "pw2", control)

    # Generate deniable control data (decrypts to a different message)
    fake_control = generate_deniable_control(ciphertext, "pw1", "pw2", b"decoy message")
    decoy = decrypt(ciphertext, "pw1", "pw2", fake_control)  # b"decoy message"
"""

from deny_sh.core import (
    encrypt,
    decrypt,
    generate_deniable_control,
    generate_control_data,
    derive_key,
    SALT_LENGTH,
    IV_LENGTH,
    KEY_LENGTH,
    HEADER_LENGTH,
    LENGTH_PREFIX,
)

__version__ = "1.0.0"
__all__ = [
    "encrypt",
    "decrypt",
    "generate_deniable_control",
    "generate_control_data",
    "derive_key",
    "SALT_LENGTH",
    "IV_LENGTH",
    "KEY_LENGTH",
    "HEADER_LENGTH",
    "LENGTH_PREFIX",
    "__version__",
]
