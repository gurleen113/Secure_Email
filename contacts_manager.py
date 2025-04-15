# src/contacts_manager.py

import os

CONTACTS_DIR = "contacts"

def store_public_key(contact_email, key_pem):
    safe_email = contact_email.replace("@", "_at_").replace(".", "_")
    os.makedirs(CONTACTS_DIR, exist_ok=True)
    file_path = os.path.join(CONTACTS_DIR, f"{safe_email}.pem")
    with open(file_path, "w") as f:
        f.write(key_pem)


def retrieve_public_key(contact_email):
    """
    Retrieve the contact's public key from contacts/<safe_email>.pem, or None if not found.
    """
    safe_email = contact_email.replace("@", "_at_").replace(".", "_")
    file_path = os.path.join(CONTACTS_DIR, f"{safe_email}.pem")
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r") as f:
        return f.read()


def load_contacts():
    """
    Load all contacts' public keys from the contacts directory.
    Returns a dictionary where keys are the contact's email (safe version) and
    values are the public key PEM strings.
    """
    contacts = {}
    if not os.path.exists(CONTACTS_DIR):
        return contacts
    for filename in os.listdir(CONTACTS_DIR):
        if filename.endswith(".pem"):
            safe_email = filename[:-4]  # remove '.pem' extension
            file_path = os.path.join(CONTACTS_DIR, filename)
            with open(file_path, "r") as f:
                contacts[safe_email] = f.read()
    return contacts
