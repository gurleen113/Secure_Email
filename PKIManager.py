import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class PKIManager:
    # Handles RSA key generation and loading
    @staticmethod
    def _safe_email(email: str) -> str:
        return email.replace("@", "_at_").replace(".", "_")

    @classmethod
    def generate_rsa_key_pair(cls, email: str, key_size: int = 2048):
        # Generate random RSA key pair and save to the directory keys/<safe_email>_private.pem and _public.pem
        key_dir = "keys"
        os.makedirs(key_dir, exist_ok=True)
        safe = cls._safe_email(email)
        privk_path = f"{key_dir}/{safe}_private.pem"
        pubk_path = f"{key_dir}/{safe}_public.pem"

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()

        with open(privk_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pubk_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return private_key, public_key

    @classmethod
    def get_rsa_key_pair(cls, email: str, key_size: int = 2048):
        # Load or generate RSA key pair
        key_dir = "keys"
        safe = cls._safe_email(email)
        priv_path = f"{key_dir}/{safe}_private.pem"
        pub_path = f"{key_dir}/{safe}_public.pem"
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
            return priv, pub
        else:
            return cls.generate_rsa_key_pair(email, key_size)

    @staticmethod
    def load_private_key(path: str):
        # Load PEM private key
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_public_key(path: str):
        # Load PEM public key
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())