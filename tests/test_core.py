"""
deny-sh Python SDK — Comprehensive test suite.

Tests algorithm compatibility with the TypeScript reference implementation,
including Known Answer Test (KAT) vectors for cross-SDK verification.
"""

import os
import struct
import pytest
from deny_sh import (
    encrypt,
    decrypt,
    generate_deniable_control,
    generate_control_data,
    derive_key,
    HEADER_LENGTH,
    SALT_LENGTH,
    IV_LENGTH,
    KEY_LENGTH,
    LENGTH_PREFIX,
)


# Passwords used in the TypeScript test suite
PW1 = "agent0018765432!unconditional"
PW2 = "unconditional1234567Bagent001"


# ─── Basic encrypt/decrypt ───


class TestBasicEncryptDecrypt:
    def test_encrypt_and_decrypt_message(self):
        message = b"Meet Me At 2pm Tomorrow"
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_encrypt_and_decrypt_empty_message(self):
        message = b""
        control_data = generate_control_data(4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_encrypt_and_decrypt_large_data(self):
        message = bytes(i % 256 for i in range(1024 * 100))  # 100KB
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_different_ciphertext_each_time(self):
        """Random salt+IV means different ciphertext each encryption."""
        message = b"Same message"
        control_data = generate_control_data(len(message) + 4)
        c1, _ = encrypt(message, PW1, PW2, control_data)
        c2, _ = encrypt(message, PW1, PW2, control_data)
        assert c1 != c2

    def test_wrong_password_produces_garbage(self):
        message = b"Secret"
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, "wrong", PW2, ctrl)
        assert plaintext != message

    def test_wrong_control_data_produces_garbage(self):
        message = b"Secret"
        control_data = generate_control_data(len(message) + 4)
        wrong_control = generate_control_data(len(message) + 4)
        ciphertext, _ = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, wrong_control)
        assert plaintext != message

    def test_reject_short_control_data(self):
        message = b"Hello world"
        short_control = generate_control_data(3)
        with pytest.raises(ValueError, match=r"Control data.*must be"):
            encrypt(message, PW1, PW2, short_control)

    def test_auto_generate_control_data(self):
        """When control_data is None, it should be auto-generated."""
        message = b"Auto control"
        ciphertext, ctrl = encrypt(message, PW1, PW2)
        assert ctrl is not None
        assert len(ctrl) == len(message) + 4
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_ciphertext_header_format(self):
        """Ciphertext should be salt(32) + iv(16) + encrypted payload."""
        message = b"Test"
        control_data = generate_control_data(len(message) + 4)
        ciphertext, _ = encrypt(message, PW1, PW2, control_data)
        # Total = 48 header + 4 length prefix + len(message)
        assert len(ciphertext) == HEADER_LENGTH + LENGTH_PREFIX + len(message)

    def test_short_ciphertext_raises(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt(b"short", PW1, PW2, b"\x00" * 10)


# ─── Deniable encryption ───


class TestDeniableEncryption:
    def test_deniable_control_decrypts_to_different_message(self):
        real_message = b"Meet Me At 2pm Tomorrow"
        fake_message = b"Kill KyK In One Month"
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)

        # Verify real decryption
        assert decrypt(ciphertext, PW1, PW2, ctrl) == real_message

        # Generate deniable control
        fake_control = generate_deniable_control(ciphertext, PW1, PW2, fake_message)

        # Same ciphertext + same passwords + different control = different message
        assert decrypt(ciphertext, PW1, PW2, fake_control) == fake_message

    def test_shorter_fake_message(self):
        real_message = b"This is a long secret message with details"
        fake_message = b"Nothing here"
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)
        fake_control = generate_deniable_control(ciphertext, PW1, PW2, fake_message)
        assert decrypt(ciphertext, PW1, PW2, fake_control) == fake_message

    def test_multiple_deniable_messages(self):
        real_message = b"The real secret"
        fake1 = b"Fake message 1"
        fake2 = b"Fake message 2"
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)

        control1 = generate_deniable_control(ciphertext, PW1, PW2, fake1)
        control2 = generate_deniable_control(ciphertext, PW1, PW2, fake2)

        assert decrypt(ciphertext, PW1, PW2, control1) == fake1
        assert decrypt(ciphertext, PW1, PW2, control2) == fake2
        assert control1 != control2

    def test_deniable_with_unicode(self):
        real_message = b"Secret plans that are quite long for testing"
        fake_message = "日本語テスト".encode("utf-8")
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)
        fake_control = generate_deniable_control(ciphertext, PW1, PW2, fake_message)
        assert decrypt(ciphertext, PW1, PW2, fake_control) == fake_message

    def test_deniable_with_empty_fake(self):
        real_message = b"Real secret"
        fake_message = b""
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)
        fake_control = generate_deniable_control(ciphertext, PW1, PW2, fake_message)
        assert decrypt(ciphertext, PW1, PW2, fake_control) == fake_message

    def test_deniable_same_length_fake(self):
        real_message = b"AAAA"
        fake_message = b"BBBB"
        control_data = generate_control_data(len(real_message) + 4)

        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)
        fake_control = generate_deniable_control(ciphertext, PW1, PW2, fake_message)
        assert decrypt(ciphertext, PW1, PW2, fake_control) == fake_message

    def test_reject_fake_too_long(self):
        real_message = b"Short"
        control_data = generate_control_data(len(real_message) + 4)
        ciphertext, ctrl = encrypt(real_message, PW1, PW2, control_data)

        too_long = b"\x00" * 1000
        with pytest.raises(ValueError, match="too long"):
            generate_deniable_control(ciphertext, PW1, PW2, too_long)


# ─── Key derivation ───


class TestKeyDerivation:
    def test_consistent_keys_same_inputs(self):
        salt = bytes(32)
        k1 = derive_key("pass1", "pass2", salt)
        k2 = derive_key("pass1", "pass2", salt)
        assert k1 == k2

    def test_different_keys_different_passwords(self):
        salt = bytes(32)
        k1 = derive_key("pass1", "pass2", salt)
        k2 = derive_key("pass1", "pass3", salt)
        assert k1 != k2

    def test_different_keys_different_salts(self):
        salt1 = bytes(32)
        salt2 = bytes([1] * 32)
        k1 = derive_key("pass1", "pass2", salt1)
        k2 = derive_key("pass1", "pass2", salt2)
        assert k1 != k2

    def test_password_order_matters(self):
        salt = bytes(32)
        k1 = derive_key("alpha", "beta", salt)
        k2 = derive_key("beta", "alpha", salt)
        assert k1 != k2


# ─── Cross-compatibility KAT vectors (from TypeScript) ───


class TestKATCrossCompatibility:
    """
    Known Answer Test vectors generated from the TypeScript reference implementation.
    These ensure byte-for-byte compatibility between SDKs.
    """

    def test_derive_key_kat(self):
        """deriveKey('password1', 'password2', salt=0xAA*32) must match TypeScript."""
        salt = bytes([0xAA] * 32)
        key = derive_key("password1", "password2", salt)
        expected = bytes.fromhex(
            "73dd642b75d80ca9423516905f4f7e990188612e7e1a1b7a28f5c8a6f21203a7"
        )
        assert key == expected

    def test_derive_key_kat2(self):
        """deriveKey('test-pw1', 'test-pw2', salt=0x01*32) must match TypeScript."""
        salt = bytes([0x01] * 32)
        key = derive_key("test-pw1", "test-pw2", salt)
        expected = bytes.fromhex(
            "ed672cc011ceec68e8d746251bdd390580bb009a1d64c75fa58f233c877ec1b6"
        )
        assert key == expected

    def test_full_encrypt_decrypt_kat(self):
        """
        Full encrypt/decrypt with fixed salt, IV, and control data
        must produce byte-identical ciphertext to TypeScript.

        Parameters:
          pw1 = 'test-pw1', pw2 = 'test-pw2'
          salt = 0x01 * 32, iv = 0x02 * 16
          message = b'Hello, World!'
          control_data = 0x03 * (len(message) + 4)
        """
        from Crypto.Cipher import AES

        pw1 = "test-pw1"
        pw2 = "test-pw2"
        fixed_salt = bytes([0x01] * 32)
        fixed_iv = bytes([0x02] * 16)
        message = b"Hello, World!"
        control_data = bytes([0x03] * (len(message) + 4))

        # Derive key
        key = derive_key(pw1, pw2, fixed_salt)
        assert key == bytes.fromhex(
            "ed672cc011ceec68e8d746251bdd390580bb009a1d64c75fa58f233c877ec1b6"
        )

        # Build payload: 4-byte LE length + plaintext
        payload = struct.pack("<I", len(message)) + message
        assert payload.hex() == "0d00000048656c6c6f2c20576f726c6421"

        # XOR with control data
        xored = bytes(payload[i] ^ control_data[i] for i in range(len(payload)))
        assert xored.hex() == "0e0303034b666f6f6c2f23546c716f6722"

        # AES-256-CTR encrypt
        cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=fixed_iv)
        encrypted = cipher.encrypt(xored)
        assert encrypted.hex() == "0eb73cf8af6fb16234fa5419946cca00e0"

        # Full ciphertext
        full_ct = fixed_salt + fixed_iv + encrypted
        expected_ct = bytes.fromhex(
            "0101010101010101010101010101010101010101010101010101010101010101"
            "020202020202020202020202020202020eb73cf8af6fb16234fa5419946cca00e0"
        )
        assert full_ct == expected_ct

        # Verify decryption via the library
        plaintext = decrypt(full_ct, pw1, pw2, control_data)
        assert plaintext == message

    def test_ciphertext_format_matches_typescript(self):
        """
        Verify the ciphertext structure:
          - First 32 bytes: salt
          - Next 16 bytes: IV
          - Remainder: AES-256-CTR(scrypt_key, payload XOR control_data)
        """
        message = b"Test"
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)

        assert len(ciphertext) == HEADER_LENGTH + LENGTH_PREFIX + len(message)
        assert HEADER_LENGTH == 48
        assert SALT_LENGTH == 32
        assert IV_LENGTH == 16


# ─── Unicode messages ───


class TestUnicodeMessages:
    def test_unicode_roundtrip(self):
        message = "Привет мир 🌍 こんにちは".encode("utf-8")
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_emoji_roundtrip(self):
        message = "🔐🗝️🔑💀🎭".encode("utf-8")
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_chinese_japanese_korean(self):
        message = "中文 日本語 한국어".encode("utf-8")
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_arabic_hebrew(self):
        message = "مرحبا שלום".encode("utf-8")
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message


# ─── Multiple message lengths ───


class TestMessageLengths:
    @pytest.mark.parametrize(
        "length", [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1000, 10000]
    )
    def test_various_lengths(self, length):
        message = bytes(i % 256 for i in range(length))
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)
        plaintext = decrypt(ciphertext, PW1, PW2, ctrl)
        assert plaintext == message

    def test_single_byte_messages(self):
        """Every possible single byte value."""
        for b in range(256):
            msg = bytes([b])
            control_data = generate_control_data(5)
            ct, ctrl = encrypt(msg, PW1, PW2, control_data)
            pt = decrypt(ct, PW1, PW2, ctrl)
            assert pt == msg


# ─── Security properties ───


class TestSecurityProperties:
    def test_ciphertext_high_entropy(self):
        """Repetitive plaintext should still produce high-entropy ciphertext."""
        message = b"A" * 500
        control_data = generate_control_data(len(message) + 4)
        ciphertext, _ = encrypt(message, PW1, PW2, control_data)

        enc_portion = ciphertext[HEADER_LENGTH:]
        # Count unique bytes as a rough entropy check
        unique = len(set(enc_portion))
        assert unique > 100, f"Only {unique} unique bytes in ciphertext — too low"

    def test_wrong_password_no_error_just_garbage(self):
        """CTR mode doesn't throw on wrong password — just garbles."""
        message = b"Secret message"
        control_data = generate_control_data(len(message) + 4)
        ciphertext, ctrl = encrypt(message, "right1", "right2", control_data)

        # Should not raise, just return garbage
        plaintext = decrypt(ciphertext, "wrong1", "wrong2", ctrl)
        assert plaintext != message

    def test_wrong_control_no_error_just_garbage(self):
        message = b"Real secret"
        control_data = generate_control_data(256)
        wrong_control = generate_control_data(256)
        ciphertext, _ = encrypt(message, PW1, PW2, control_data)

        plaintext = decrypt(ciphertext, PW1, PW2, wrong_control)
        assert plaintext != message

    def test_100_unique_ciphertexts(self):
        """Same plaintext + passwords produce 100 unique ciphertexts."""
        message = b"Same message every time"
        control_data = generate_control_data(len(message) + 4)

        seen = set()
        for _ in range(100):
            ct, _ = encrypt(message, PW1, PW2, control_data)
            seen.add(ct)
        assert len(seen) == 100

    def test_ciphertext_invariance_during_denial(self):
        """generateDeniableControl never mutates the ciphertext."""
        message = b"Real secret message"
        control_data = generate_control_data(256)
        ciphertext, ctrl = encrypt(message, PW1, PW2, control_data)

        ct_copy = bytes(ciphertext)
        for i in range(50):
            fake = f"Fake message {i}".encode()
            generate_deniable_control(ciphertext, PW1, PW2, fake)
            assert ciphertext == ct_copy


# ─── Constants check ───


class TestConstants:
    def test_salt_length(self):
        assert SALT_LENGTH == 32

    def test_iv_length(self):
        assert IV_LENGTH == 16

    def test_key_length(self):
        assert KEY_LENGTH == 32

    def test_header_length(self):
        assert HEADER_LENGTH == 48

    def test_length_prefix(self):
        assert LENGTH_PREFIX == 4
