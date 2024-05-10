import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class HybridCryptosystem:
    def _init_(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()

    def generate_keys(self):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def aes_encrypt(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def aes_decrypt(self, ciphertext, key):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        return plaintext

    def ecdh_key_exchange(self, private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key

    def hybrid_encrypt(self, plaintext, peer_public_key):
        private_key, own_public_key = self.generate_keys()
        shared_key = self.ecdh_key_exchange(private_key, peer_public_key)
        ciphertext = self.aes_encrypt(plaintext, shared_key)
        return own_public_key, ciphertext

    def hybrid_decrypt(self, own_private_key, sender_public_key, ciphertext):
        shared_key = self.ecdh_key_exchange(own_private_key, sender_public_key)
        plaintext = self.aes_decrypt(ciphertext, shared_key)
        return plaintext

if _name_ == "_main_":
    plaintext = b"Hello, this is a test message for encryption and decryption."

    # Initialize the cryptosystem
    cryptosystem = HybridCryptosystem()

    # Alice encrypts a message for Bob
    alice_private_key, alice_public_key = cryptosystem.generate_keys()
    bob_private_key, bob_public_key = cryptosystem.generate_keys()
    print("Plaintext:", plaintext.decode())

    # Encrypt the message
    sender_public_key, ciphertext = cryptosystem.hybrid_encrypt(plaintext, bob_public_key)
    print("Encrypted Text:", ciphertext.hex())
    print("Sender Public Key (for decryption):", sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    )

    # Bob decrypts the message
    decrypted_plaintext = cryptosystem.hybrid_decrypt(bob_private_key, sender_public_key, ciphertext)
    print("Decrypted Plaintext:", decrypted_plaintext.decode())