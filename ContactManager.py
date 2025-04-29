import os
from PKIManager import PKIManager

class ContactManager:
    # Contact public key storage
    def __init__(self, directory: str = "contacts"):
        os.makedirs(directory, exist_ok=True)
        self.dir = directory

    def store_public_key(self, contact_email: str, key_pem: str):
        # Use the PKIManager class method correctly
        safe = PKIManager._safe_email(contact_email)
        path = os.path.join(self.dir, f"{safe}.pem")
        with open(path, "w") as f:
            f.write(key_pem)

    def retrieve_public_key(self, contact_email: str) -> str | None:
        # Use the PKIManager class method correctly
        safe = PKIManager._safe_email(contact_email)
        path = os.path.join(self.dir, f"{safe}.pem")
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return f.read()

    def load_contacts(self) -> dict:
        contacts = {}
        if not os.path.exists(self.dir):
            return contacts
            
        for fn in os.listdir(self.dir):
            if fn.endswith(".pem"):
                safe = fn[:-4]
                with open(os.path.join(self.dir, fn), "r") as f:
                    contacts[safe] = f.read()
        return contacts