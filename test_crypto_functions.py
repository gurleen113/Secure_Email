from CryptoHandler import CryptoHandler
from Signer import Signer
from PKIManager import PKIManager

# --- AES Encryption/Decryption Test ---
message = "Test message for AES."
encrypted_message, aes_key = CryptoHandler.aes_encrypt(message)
decrypted_message = CryptoHandler.aes_decrypt(encrypted_message, aes_key)

assert decrypted_message == message
print("AES Encryption/Decryption Test Passed.")

# --- RSA Encryption/Decryption Test ---
priv_key, pub_key = PKIManager.generate_rsa_key_pair("test@example.com")

test_aes_key = b"thisisasecretkey123"  # Must be bytes
encrypted_aes_key = CryptoHandler.rsa_encrypt_key(test_aes_key, pub_key)
decrypted_aes_key = CryptoHandler.rsa_decrypt_key(encrypted_aes_key, priv_key)

assert decrypted_aes_key == test_aes_key
print("RSA Encryption/Decryption Test Passed.")

# --- Digital Signature Test ---
message_bytes = b"Test message for signing."
signature = Signer.sign_data(priv_key, message_bytes)
is_valid = Signer.verify_signature(pub_key, message_bytes, signature)

assert is_valid
print("Digital Signature Test Passed.")
