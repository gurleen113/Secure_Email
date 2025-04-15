import os
import json

def load_email_providers():
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'email_providers.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        try:
            alt_path = os.path.join(os.path.dirname(__file__), 'email_providers.json')
            with open(alt_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "gmail": {
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 465,
                    "use_ssl": True,
                    "domain": "gmail.com"
                }
            }

EMAIL_PROVIDERS = load_email_providers()

def get_provider_settings(email):
    if not email or '@' not in email:
        return "unknown", None
    domain = email.split('@')[-1].lower()
    for provider, settings in EMAIL_PROVIDERS.items():
        if domain == settings["domain"] or domain.endswith('.' + settings["domain"]):
            return provider, settings
    return "custom", None

def get_provider_name(email):
    provider, _ = get_provider_settings(email)
    provider_names = {
        "gmail": "Gmail",
        "yahoo": "Yahoo Mail",
        "icloud": "iCloud Mail",
        "zoho": "Zoho Mail",
        "unknown": "Unknown Provider"
    }
    return provider_names.get(provider, "Email")

def add_custom_provider(domain, smtp_server, smtp_port, use_ssl):
    try:
        provider_id = domain.split('.')[0].lower()
        EMAIL_PROVIDERS[provider_id] = {
            "smtp_server": smtp_server,
            "smtp_port": int(smtp_port),
            "use_ssl": bool(use_ssl),
            "domain": domain
        }
        try:
            config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, 'email_providers.json')
            with open(config_path, 'w') as f:
                json.dump(EMAIL_PROVIDERS, f, indent=2)
            return True
        except (FileNotFoundError, PermissionError):
            alt_path = os.path.join(os.path.dirname(__file__), 'email_providers.json')
            with open(alt_path, 'w') as f:
                json.dump(EMAIL_PROVIDERS, f, indent=2)
            return True
    except Exception as e:
        print(f"Error adding custom provider: {e}")
        return False
