import json
import base64
import smtplib
import ssl
from email.message import EmailMessage
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from CryptoHandler import CryptoHandler
from Signer import Signer
from PKIManager import PKIManager
from ContactManager import ContactManager
from EmailProvider import EmailProvider
from utils import delete_directory

class EmailService:
    # Build payloads and send emails
    def __init__(self):
        self.crypto = CryptoHandler()
        self.signer = Signer()
        self.contacts = ContactManager()
        self.provider = EmailProvider()

    def create_secure_email_payload(self, message: str, sender_priv, receiver_pub) -> list:
        enc_msg, aes_key = self.crypto.aes_encrypt(message)
        enc_key = self.crypto.rsa_encrypt_key(aes_key, receiver_pub)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
        signature = self.signer.sign_data(sender_priv, digest.finalize())
        return [
            base64.b64encode(enc_msg).decode(),
            base64.b64encode(enc_key).decode(),
            base64.b64encode(signature).decode()
        ]

    def send_secure_email(self, subject: str, body: str,
                          sender_email: str, app_password: str,
                          recipient_email: str, smtp_settings=None):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg.set_content(body)

        if smtp_settings is None:
            _, smtp_settings = self.provider.get_provider_settings(sender_email)

        if smtp_settings.get("use_ssl"):
            contx = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_settings["smtp_server"],
                                  smtp_settings["smtp_port"],
                                  context=contx) as server:
                server.login(sender_email, app_password)
                server.send_message(msg)
        else:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(smtp_settings["smtp_server"],
                              smtp_settings["smtp_port"]) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.ehlo()
                server.login(sender_email, app_password)
                server.send_message(msg)

    def send_full_secure_email(self, message: str, app_password: str,
                               recipient_email: str, sender_email: str,
                               smtp_settings=None, subject: str = "Secure Email"):
        try:
            sender_priv, _ = PKIManager.get_rsa_key_pair(sender_email)
        except Exception as ex:
            return False, f"Error loading sender keys: {ex}"

        pub_pem = self.contacts.retrieve_public_key(recipient_email)
        if not pub_pem:
            return False, f"No stored public key for {recipient_email}."

        try:
            receiver_pub = serialization.load_pem_public_key(pub_pem.encode())
        except Exception as ex:
            return False, f"Error loading recipient public keyplease check or update the public key.\nError: {ex}"

        try:
            payload = self.create_secure_email_payload(message, sender_priv, receiver_pub)
        except Exception as ex:
            return False, f"Error creating payload: {ex}"

        try:
            self.send_secure_email(subject, json.dumps(payload),
                                   sender_email, app_password,
                                   recipient_email, smtp_settings)
            return True, "Secure email sent successfully!"
        except Exception as ex:
            return False, f"Error sending email: {ex}"

    def cleanup_data(self):
        for folder in ["keys", "contacts"]:
            try:
                delete_directory(folder)
            except Exception as e:
                print(f"Error deleting {folder}: {e}")
