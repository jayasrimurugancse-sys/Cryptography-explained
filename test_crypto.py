import unittest
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.crypto_examples import sha256_text, encrypt_message, decrypt_message
from src.hash_compare import compare


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = AESGCM.generate_key(bit_length=256)
        self.message = b"dummy classroom message"

    def test_sha256_known_vector(self):
        self.assertEqual(sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_digest_shape_and_determinism(self):
        self.assertEqual(len(sha256_text("hello")), 64)
        self.assertEqual(sha256_text("hello"), sha256_text("hello"))
        self.assertNotEqual(sha256_text("Hello"), sha256_text("hello"))

    def test_round_trip_unicode(self):
        value = "Hello CSE - नमस्ते".encode()
        nonce, ct = encrypt_message(self.key, value)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(decrypt_message(self.key, nonce, ct), value)

    def test_empty_plaintext(self):
        nonce, ct = encrypt_message(self.key, b"")
        self.assertEqual(decrypt_message(self.key, nonce, ct), b"")

    def test_tamper_rejected(self):
        nonce, ct = encrypt_message(self.key, self.message)
        with self.assertRaises(InvalidTag):
            decrypt_message(self.key, nonce, bytes([ct[0] ^ 1]) + ct[1:])

    def test_wrong_key_rejected(self):
        nonce, ct = encrypt_message(self.key, self.message)
        with self.assertRaises(InvalidTag):
            decrypt_message(AESGCM.generate_key(bit_length=256), nonce, ct)

    def test_wrong_aad_rejected(self):
        nonce, ct = encrypt_message(self.key, self.message)
        with self.assertRaises(InvalidTag):
            decrypt_message(self.key, nonce, ct, b"wrong context")

    def test_wrong_nonce_rejected(self):
        nonce, ct = encrypt_message(self.key, self.message)
        wrong = bytes([nonce[0] ^ 1]) + nonce[1:]
        with self.assertRaises(InvalidTag):
            decrypt_message(self.key, wrong, ct)

    def test_signature_and_changed_message(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(self.message)
        key.public_key().verify(sig, self.message)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(sig, b"changed")

    def test_wrong_signer_rejected(self):
        key = Ed25519PrivateKey.generate()
        with self.assertRaises(InvalidSignature):
            Ed25519PrivateKey.generate().public_key().verify(key.sign(self.message), self.message)

    def test_hash_comparison(self):
        rows = compare(["Hello", "hello", "Hello"])
        self.assertEqual(rows[0]["changed_bits_vs_first"], 0)
        self.assertGreater(rows[1]["changed_bits_vs_first"], 0)
        self.assertEqual(rows[2]["changed_bits_vs_first"], 0)


if __name__ == "__main__":
    unittest.main()
