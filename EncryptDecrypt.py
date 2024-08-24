import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC




class EncryptDecrypt:

    def __init__(self, password):
        self.password = password
        self.KDF_ALGORITHM = hashes.SHA256()
        self.KDF_LENGTH = 32
        self.KDF_ITERATIONS = 120000

    def encrypt(self, plaintext: str):
        # Derive a symmetric key using the passsword and a fresh random salt.
        salt =  secrets.token_bytes(64)
        kdf = PBKDF2HMAC(
            algorithm=self.KDF_ALGORITHM, length=self.KDF_LENGTH, salt=salt,
            iterations=self.KDF_ITERATIONS)
        key = kdf.derive(self.password.encode("utf-8"))

        # Encrypt the message.
        f = Fernet(base64.urlsafe_b64encode(key))
        ciphertext = f.encrypt(plaintext.encode("utf-8"))

        return ciphertext, salt

    def decrypt(self, ciphertext: bytes, salt: bytes) -> str:
        # Derive the symmetric key using the password and provided salt.
        kdf = PBKDF2HMAC(
            algorithm=self.KDF_ALGORITHM, length=self.KDF_LENGTH, salt=salt,
            iterations=self.KDF_ITERATIONS)
        key = kdf.derive(self.password.encode("utf-8"))

        # Decrypt the message
        f = Fernet(base64.urlsafe_b64encode(key))
        plaintext = f.decrypt(ciphertext)

        return plaintext.decode("utf-8")