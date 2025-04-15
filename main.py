import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from encryption import aes_encrypt, rsa_encrypt_key
from hashing_signature import sign_data
from network import send_secure_email
from email_provider import get_provider_settings
from contacts_manager import retrieve_public_key  # Retrieves recipient public key from contacts/<safe_email>.pem


def load_user_key(user_email, is_private):
    """Load the sender's key from the 'keys' folder (filename is based on a safe version of the email)."""
    safe_email = user_email.replace("@", "_at_").replace(".", "_")
    key_path = f"keys/{safe_email}_{'private' if is_private else 'public'}.pem"
    with open(key_path, "rb") as key_file:
        if is_private:
            return serialization.load_pem_private_key(key_file.read(), password=None)
        else:
            return serialization.load_pem_public_key(key_file.read())


def create_secure_email_payload(message, sender_private, receiver_public, sender_public):
    """Encrypt message with symmetric encryption and encrypt the symmetric key with the recipient's public key.
    Sign the message as well."""
    encrypted_msg, aes_key = aes_encrypt(message)
    encrypted_key = rsa_encrypt_key(aes_key, receiver_public)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    hashed_msg = digest.finalize()
    signature = sign_data(hashed_msg, sender_private)
    payload = {
        "encrypted_message": base64.b64encode(encrypted_msg).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "signature": base64.b64encode(signature).decode()
    }
    return payload


def send_full_secure_email(message, app_password, recipient_email, sender_email, smtp_settings=None):
    """Send an encrypted email from sender_email to recipient_email.
       The recipient's public key is loaded from the contacts folder."""
    try:
        sender_private = load_user_key(sender_email, True)
        sender_public = load_user_key(sender_email, False)
    except Exception as e:
        return False, f"Error loading sender keys: {e}"

    public_key_pem = retrieve_public_key(recipient_email)
    if not public_key_pem:
        return False, f"No stored public key found for {recipient_email}. Please add it first in your contacts."

    try:
        recipient_public = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception as e:
        return False, f"Error loading recipient public key: {e}"

    try:
        payload = create_secure_email_payload(message, sender_private, recipient_public, sender_public)
    except Exception as e:
        return False, f"Error creating secure payload: {e}"

    try:
        send_secure_email("Secure Email", json.dumps(payload), sender_email, app_password, recipient_email,
                          smtp_settings)
        return True, "Secure email sent successfully!"
    except Exception as e:
        return False, f"Error sending email: {e}"


if __name__ == "__main__":
    # For testing from the command line:
    sender_email = input("Your email: ").strip()
    recipient_email = input("Recipient email: ").strip()
    app_password = input("Your email/app password: ").strip()
    message = input("Your message: ").strip()
    provider, smtp_settings = get_provider_settings(sender_email)
    success, msg = send_full_secure_email(message, app_password, recipient_email, sender_email, smtp_settings)
    print(msg)
