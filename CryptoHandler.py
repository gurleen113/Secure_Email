from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

class CryptoHandler:   # AES and RSA message encryption/decryption
    @staticmethod
    def aes_encrypt(message: str):
        key = Fernet.generate_key()
        token = Fernet(key).encrypt(message.encode())
        return token, key

    @staticmethod
    def aes_decrypt(token: bytes, key: bytes):
        return Fernet(key).decrypt(token).decode()

    @staticmethod
    def rsa_encrypt_key(aes_key: bytes, pub_key):
        return pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def rsa_decrypt_key(enc_key: bytes, priv_key):
        return priv_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )