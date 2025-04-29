import json
import os
class EmailProvider:
    # SMTP provider settings
    def __init__(self, config_path: str = None):
        import os
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "config", "email_providers.json")
        try:
            with open(config_path) as f:
                self.providers = json.load(f)
        except Exception:
            self.providers = {}

    def get_provider_settings(self, email: str):
        if "@" not in email:
            return "unknown", None
        domain = email.split("@")[-1].lower()
        for pid, cfg in self.providers.items():
            if domain == cfg.get("domain") or domain.endswith("." + cfg.get("domain", "")):
                return pid, cfg
        return "custom", None

    def get_provider_name(self, email: str) -> str:
        pid, _ = self.get_provider_settings(email)
        names = {
            "gmail": "Gmail",
            "yahoo": "Yahoo Mail",
            "icloud": "iCloud Mail",
            "zoho": "Zoho Mail",
            "unknown": "Unknown Provider"
        }
        return names.get(pid, "Email")
    # If the user has a custom provider they can add it and it will be saved in the config file
    def add_custom_provider(self, domain: str, smtp_server: str, smtp_port: int, use_ssl: bool) -> bool:
        try:
            pid = domain.split(".")[0].lower()
            self.providers[pid] = {
                "domain": domain,
                "smtp_server": smtp_server,
                "smtp_port": smtp_port,
                "use_ssl": use_ssl
            }
            cfg_dir = os.path.join(os.path.dirname(__file__), "config")
            os.makedirs(cfg_dir, exist_ok=True)
            with open(os.path.join(cfg_dir, "email_providers.json"), "w") as f:
                json.dump(self.providers, f, indent=2)
            return True
        except Exception:
            return False

