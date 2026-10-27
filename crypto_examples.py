"""Library-based examples; not a production key-management system."""
import base64
import hashlib
import os
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encrypt_message(key, plaintext, aad=b"capstone34:v1"):
    # Generate a new nonce for EVERY encryption. Never reuse with the same key.
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_message(key, nonce, ciphertext, aad=b"capstone34:v1"):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def main():
    message = b"Hello, CSE students!"
    print("SHA-256:", sha256_text(message.decode()))
    key = AESGCM.generate_key(bit_length=256)
    nonce, ciphertext = encrypt_message(key, message)
    print("AES-GCM ciphertext + tag (Base64):", base64.b64encode(ciphertext).decode())
    print("Nonce (Base64, not secret):", base64.b64encode(nonce).decode())
    print("Recovered:", decrypt_message(key, nonce, ciphertext).decode())
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    try:
        decrypt_message(key, nonce, tampered)
    except InvalidTag:
        print("PASS: altered ciphertext rejected")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    signature = private.sign(message)
    public.verify(signature, message)
    print("PASS: original signature verified")
    try:
        public.verify(signature, b"Changed message")
    except InvalidSignature:
        print("PASS: changed message rejected")
    print("Keys stay in memory and are discarded. No secrets are printed or saved.")


if __name__ == "__main__":
    main()
