# deny-sh — Python SDK

Deniable encryption for Python. Same algorithm as the [TypeScript reference implementation](https://www.npmjs.com/package/deny-sh). Ciphertext is byte-for-byte compatible across SDKs.

## Install

```bash
pip install deny-sh
```

## Quick Start

```python
from deny_sh import encrypt, decrypt, generate_deniable_control

# Encrypt a secret message
ciphertext, control = encrypt(b"seed phrase: abandon ability ...", "pw1", "pw2")

# Decrypt with the real control data
message = decrypt(ciphertext, "pw1", "pw2", control)
# b"seed phrase: abandon ability ..."

# Generate deniable control data — same ciphertext decrypts to a decoy
fake_control = generate_deniable_control(ciphertext, "pw1", "pw2", b"nothing here")
decoy = decrypt(ciphertext, "pw1", "pw2", fake_control)
# b"nothing here"
```

## How It Works

1. **Dual-password key derivation** — SHA-256(pw1) || SHA-256(pw2) → scrypt → AES-256 key
2. **XOR deniability layer** — plaintext is XOR'd with control data before encryption
3. **AES-256-CTR encryption** — standard authenticated encryption
4. **Length prefix inside encrypted zone** — no metadata leaks the real message size

The control data is what makes it deniable. Different control data + same ciphertext + same passwords = different plaintext. Both the real and fake control data look like random bytes — there's no way to tell which is "real".

## API

### `encrypt(plaintext, password1, password2, control_data=None)`

Encrypt plaintext with dual passwords and optional control data.

- **plaintext** (`bytes`) — data to encrypt
- **password1** (`str`) — first password
- **password2** (`str`) — second password
- **control_data** (`bytes | None`) — control file data; auto-generated if `None`

Returns `(ciphertext: bytes, control_data: bytes)`.

### `decrypt(ciphertext, password1, password2, control_data)`

Decrypt ciphertext with dual passwords and control data.

Returns `bytes` — the decrypted plaintext.

### `generate_deniable_control(ciphertext, password1, password2, desired_plaintext)`

Generate new control data that makes existing ciphertext decrypt to a different message.

Returns `bytes` — new control data.

### `generate_control_data(size)`

Generate cryptographically secure random control data.

Returns `bytes`.

### `derive_key(password1, password2, salt)`

Derive the AES-256 key from two passwords and a salt. Exposed for cross-implementation testing.

Returns `bytes` (32 bytes).

## Algorithm Compatibility

The ciphertext format is identical across all deny-sh SDKs:

```
salt (32 bytes) | iv (16 bytes) | AES-256-CTR(key, payload XOR control_data)
```

Where `payload = length_prefix (4 bytes LE) + plaintext`.

KDF parameters: scrypt(N=16384, r=8, p=1, dklen=32).

A file encrypted with the Python SDK can be decrypted with the TypeScript SDK, and vice versa.

## Dependencies

- **pycryptodome** — AES-256-CTR encryption
- **hashlib** (stdlib) — SHA-256 and scrypt KDF
- **os** (stdlib) — `urandom` for secure random bytes

## License

AGPL-3.0. [Commercial licenses](https://deny.sh/docs#commercial) available.
