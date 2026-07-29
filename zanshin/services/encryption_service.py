import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionService:
    def __init__(self):
        # Default fallback key, kept for backward compatibility with data
        # encrypted by an earlier implementation of this application
        self.key = os.getenv("ENCRYPTION_KEY", "my-secret-encryption-key-32bytes").encode("utf-8")
        if len(self.key) < 32:
            self.key = self.key.ljust(32, b"\0")[:32]
        elif len(self.key) > 32:
            self.key = self.key[:32]

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return plain_text
        try:
            aesgcm = AESGCM(self.key)
            iv = os.urandom(12)
            ciphertext = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)
            # Prepend IV to ciphertext
            combined = iv + ciphertext
            return base64.b64encode(combined).decode("utf-8")
        except Exception as e:
            raise RuntimeError("Error encrypting value") from e

    def decrypt(self, encrypted_text: str) -> str:
        if not encrypted_text:
            return encrypted_text
        try:
            combined = base64.b64decode(encrypted_text.encode("utf-8"))
            iv = combined[:12]
            ciphertext = combined[12:]
            aesgcm = AESGCM(self.key)
            decrypted = aesgcm.decrypt(iv, ciphertext, None)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise RuntimeError("Error decrypting value") from e
