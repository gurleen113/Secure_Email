import smtplib
import ssl
from email.message import EmailMessage

def send_secure_email(subject, body, sender_email, app_password, recipient_email, smtp_settings=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg.set_content(body)

    if smtp_settings is None:
        smtp_settings = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 465,
            "use_ssl": True
        }

    if smtp_settings["use_ssl"]:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_settings["smtp_server"], smtp_settings["smtp_port"], context=context) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
            print("Email sent successfully.")
    else:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_settings["smtp_server"], smtp_settings["smtp_port"]) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
            print("Email sent successfully.")
