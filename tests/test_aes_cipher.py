import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes_cipher import DecryptionError, decrypt, encrypt  # noqa: E402


class TestAESCipher(unittest.TestCase):
    PASSWORD = "Str0ng#Pass"

    def test_round_trip(self):
        message = "Confidential: meeting at 5 PM in Lab 3"
        self.assertEqual(decrypt(encrypt(message, self.PASSWORD), self.PASSWORD), message)

    def test_unicode_and_empty_message(self):
        for message in ["", "నమస్కారం 🔐 café", "line1\nline2"]:
            self.assertEqual(decrypt(encrypt(message, self.PASSWORD), self.PASSWORD), message)

    def test_ciphertext_is_different_each_time(self):
        # Random salt + nonce means the same message never encrypts the same way
        self.assertNotEqual(encrypt("hello", self.PASSWORD), encrypt("hello", self.PASSWORD))

    def test_ciphertext_hides_plaintext(self):
        token = encrypt("topsecret", self.PASSWORD)
        self.assertNotIn(b"topsecret", base64.b64decode(token))

    def test_wrong_password_fails(self):
        token = encrypt("hello", self.PASSWORD)
        with self.assertRaises(DecryptionError):
            decrypt(token, "wrong-password")

    def test_tampered_ciphertext_fails(self):
        data = bytearray(base64.b64decode(encrypt("hello", self.PASSWORD)))
        data[-1] ^= 0x01  # flip one bit
        with self.assertRaises(DecryptionError):
            decrypt(base64.b64encode(bytes(data)).decode(), self.PASSWORD)

    def test_invalid_input_fails(self):
        with self.assertRaises(DecryptionError):
            decrypt("not base64 !!", self.PASSWORD)
        with self.assertRaises(DecryptionError):
            decrypt(base64.b64encode(b"short").decode(), self.PASSWORD)

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            encrypt("hello", "")


if __name__ == "__main__":
    unittest.main()
