import base64
import json
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# ---------- Constants ----------
ENCRYPTION_ITERATIONS = 1_000_000
SALT_SIZE = 16

# ---------- Encryption Module ----------
class Encryption:
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = ENCRYPTION_ITERATIONS) -> bytes:
        pw = password.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(pw))

    @staticmethod
    def encrypt_db(data: dict, password: str, salt: bytes) -> bytes:
        key = Encryption.derive_key(password, salt)
        f = Fernet(key)
        return f.encrypt(json.dumps(data).encode("utf-8"))

    @staticmethod
    def decrypt_db(token: bytes, password: str, salt: bytes) -> dict:
        key = Encryption.derive_key(password, salt)
        f = Fernet(key)
        plaintext = f.decrypt(token)
        return json.loads(plaintext.decode("utf-8"))

    @staticmethod
    def save_file(path: str, db: dict, password: str) -> None:
        salt = secrets.token_bytes(SALT_SIZE)
        encrypted = Encryption.encrypt_db(db, password, salt)
        with open(path, "wb") as f:
            f.write(salt + encrypted)

    @staticmethod
    def load_file(path: str, password: str) -> dict:
        with open(path, "rb") as f:
            raw = f.read()
        salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
        return Encryption.decrypt_db(token, password, salt)