import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Generate a new random RSA key pair and store it
def generate_random_rsa_key_pair(email, key_size=2048):
    key_dir = "keys"
    os.makedirs(key_dir, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_")
    private_key_path = f"{key_dir}/{safe_email}_private.pem"
    public_key_path = f"{key_dir}/{safe_email}_public.pem"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key


# Deterministic RSA key generation using a recovery passphrase.
# (Requires pycryptodomex; ensure you install it with: pip install pycryptodomex)
def generate_deterministic_rsa_key_pair(email, key_recovery, key_size=2048):
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Hash import SHA256
    from Cryptodome.Protocol.KDF import PBKDF2

    key_dir = "keys"
    os.makedirs(key_dir, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_")
    private_key_path = f"{key_dir}/{safe_email}_private.pem"
    public_key_path = f"{key_dir}/{safe_email}_public.pem"

    # Derive a seed using the recovery passphrase with the email as salt:
    seed = PBKDF2(key_recovery, email.encode(), dkLen=32, count=100000)

    # A simple deterministic RNG using SHA256 repeatedly:
    class DeterministicRNG:
        def __init__(self, seed):
            self.state = seed

        def read(self, n):
            output = b""
            while len(output) < n:
                self.state = SHA256.new(self.state).digest()
                output += self.state
            return output[:n]

    rng = DeterministicRNG(seed)
    key = RSA.generate(key_size, randfunc=rng.read)

    with open(private_key_path, "wb") as f:
        f.write(key.export_key(format="PEM"))
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key(format="PEM"))

    # Load the keys using cryptography for consistency:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


# Main function to get the RSA key pair for a given email.
# If the files exist, load them.
# If not, then if key_recovery is provided use deterministic generation;
# otherwise, generate a random key pair.
def get_rsa_key_pair(email, key_recovery=None, key_size=2048):
    key_dir = "keys"
    safe_email = email.replace("@", "_at_").replace(".", "_")
    private_key_path = os.path.join(key_dir, f"{safe_email}_private.pem")
    public_key_path = os.path.join(key_dir, f"{safe_email}_public.pem")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    else:
        if key_recovery:
            return generate_deterministic_rsa_key_pair(email, key_recovery, key_size)
        else:
            return generate_random_rsa_key_pair(email, key_size)
