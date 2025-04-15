import tkinter as tk
from tkinter import messagebox, ttk
import base64, json, re, smtplib, os, shutil
from threading import Threadgur
import stat

from main import send_full_secure_email
from email_provider import get_provider_settings, get_provider_name, add_custom_provider
from pki import get_rsa_key_pair  # This function loads or deterministically generates RSA keys using the recovery passphrase
from contacts_manager import store_public_key, retrieve_public_key  # For storing and retrieving contacts as separate PEM files
# Removed legacy import for load_contacts since it is not defined:
# from contacts_manager import load_contacts
from encryption import rsa_decrypt_key, aes_decrypt
from hashing_signature import verify_signature
from cryptography.hazmat.primitives import serialization, hashes


# Utility function to validate email format
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


# Main entry window for the application
def run_gui():
    option_window = tk.Tk()
    option_window.title("Secure Email Application")
    option_window.geometry("400x300")
    option_window.update_idletasks()
    width = option_window.winfo_width()
    height = option_window.winfo_height()
    x = (option_window.winfo_screenwidth() // 2) - (width // 2)
    y = (option_window.winfo_screenheight() // 2) - (height // 2)
    option_window.geometry(f"{width}x{height}+{x}+{y}")

    main_frame = tk.Frame(option_window)
    main_frame.pack(expand=True, fill="both", padx=30, pady=30)
    tk.Label(main_frame, text="Secure Email Application", font=("Arial", 16, "bold")).pack(pady=(0, 20))
    tk.Label(main_frame, text="Choose an option:", font=("Arial", 12)).pack(pady=(0, 30))

    def open_login_option():
        option_window.destroy()
        show_login_page()

    login_button = tk.Button(main_frame, text="Login", command=open_login_option,
                             width=20, height=2, font=("Arial", 11, "bold"), bg="#008000", fg="white")
    login_button.pack(pady=(0, 15))
    option_window.mainloop()


# Login page that requires a Key Recovery Passphrase (not optional)
def show_login_page():
    login_window = tk.Tk()
    login_window.title("Login - Secure Email")
    login_window.geometry("500x750")
    login_window.update_idletasks()
    width = login_window.winfo_width()
    height = login_window.winfo_height()
    x = (login_window.winfo_screenwidth() // 2) - (width // 2)
    y = (login_window.winfo_screenheight() // 2) - (height // 2)
    login_window.geometry(f"{width}x{height}+{x}+{y}")

    login_frame = tk.Frame(login_window)
    login_frame.pack(expand=True, fill="both", padx=20, pady=20)

    def go_back():
        login_window.destroy()
        run_gui()

    tk.Button(login_frame, text="← Back", command=go_back, anchor="w").pack(anchor="w", pady=(0, 15))
    tk.Label(login_frame, text="Login to Secure Email", font=("Arial", 16, "bold")).pack(pady=(0, 30))

    tk.Label(login_frame, text="Email Address:", font=("Arial", 12)).pack(pady=(0, 10))
    email_var = tk.StringVar()
    email_entry = tk.Entry(login_frame, textvariable=email_var, width=40, font=("Arial", 11))
    email_entry.pack(pady=(0, 20), ipady=8)

    # Key Recovery Passphrase (REQUIRED)
    tk.Label(login_frame, text="Key Recovery Passphrase:", font=("Arial", 12)).pack(pady=(0, 10))
    key_pass_var = tk.StringVar()
    key_pass_entry = tk.Entry(login_frame, textvariable=key_pass_var, width=40, font=("Arial", 11), show="*")
    key_pass_entry.pack(pady=(0, 20), ipady=8)
    tk.Label(login_frame,
             text="(This passphrase is required to deterministically generate your unique RSA keys. Keep it secure!)",
             font=("Arial", 9), fg="gray").pack(pady=(0, 20))

    # SMTP provider fields
    provider_label = tk.Label(login_frame, text="", font=("Arial", 10), fg="blue")
    smtp_frame = tk.LabelFrame(login_frame, text="SMTP Server Settings", font=("Arial", 11), padx=15, pady=15)
    smtp_server_var = tk.StringVar()
    smtp_port_var = tk.StringVar(value="465")
    use_ssl_var = tk.BooleanVar(value=True)
    tk.Label(smtp_frame, text="SMTP Server:", font=("Arial", 11)).grid(row=0, column=0, sticky="w", pady=8)
    tk.Entry(smtp_frame, textvariable=smtp_server_var, width=30, font=("Arial", 11)).grid(row=0, column=1, sticky="ew",
                                                                                          pady=8)
    tk.Label(smtp_frame, text="SMTP Port:", font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=8)
    tk.Entry(smtp_frame, textvariable=smtp_port_var, width=10, font=("Arial", 11)).grid(row=1, column=1, sticky="w",
                                                                                        pady=8)
    tk.Checkbutton(smtp_frame, text="Use SSL", variable=use_ssl_var, font=("Arial", 11)).grid(row=2, column=0,
                                                                                              columnspan=2, sticky="w",
                                                                                              pady=8)
    tk.Label(smtp_frame, text="Common: 465 (SSL), 587 (TLS)", font=("Arial", 9), fg="gray").grid(row=1, column=1,
                                                                                                 sticky="sw",
                                                                                                 padx=(60, 0))

    def save_provider_settings():
        email = email_var.get().strip()
        smtp_server = smtp_server_var.get().strip()
        smtp_port = smtp_port_var.get().strip()
        use_ssl = use_ssl_var.get()
        if not email or not smtp_server or not smtp_port:
            messagebox.showerror("Error", "Fill in all fields")
            return
        if "@" not in email:
            messagebox.showerror("Error", "Enter a valid email")
            return
        try:
            smtp_port = int(smtp_port)
        except ValueError:
            messagebox.showerror("Error", "Port must be numeric")
            return
        domain = email.split("@")[-1].lower()
        if add_custom_provider(domain, smtp_server, smtp_port, use_ssl):
            messagebox.showinfo("Success", f"Provider settings for {domain} saved.")
        else:
            messagebox.showerror("Error", "Could not save settings.")

    tk.Button(smtp_frame, text="Save Provider Settings", command=save_provider_settings, font=("Arial", 9)).grid(row=3,
                                                                                                                 column=0,
                                                                                                                 columnspan=2,
                                                                                                                 pady=10)

    def detect_email_provider(event=None):
        email = email_var.get().strip()
        if not email:
            provider_label.config(text="")
            provider_label.pack_forget()
            return
        if "@" not in email:
            provider_label.config(text="Enter a valid email")
            provider_label.pack(pady=5)
            return
        provider, settings = get_provider_settings(email)
        provider_name = get_provider_name(email)
        if settings:
            smtp_frame.pack_forget()
            provider_label.config(text=f"Detected: {provider_name}")
            provider_label.pack(pady=5)
            smtp_server_var.set(settings["smtp_server"])
            smtp_port_var.set(str(settings["smtp_port"]))
            use_ssl_var.set(settings["use_ssl"])
        else:
            provider_label.config(text=f"Provider: {provider_name} - Manual SMTP required")
            provider_label.pack(pady=5)
            smtp_frame.pack_forget()

    email_entry.bind("<FocusOut>", detect_email_provider)
    email_entry.bind("<KeyRelease>", lambda e: login_window.after(500, detect_email_provider))

    manual_smtp_var = tk.BooleanVar(value=False)
    tk.Checkbutton(login_frame, text="Manually configure SMTP settings", variable=manual_smtp_var,
                   command=lambda: smtp_frame.pack(fill="x",
                                                   pady=15) if manual_smtp_var.get() else smtp_frame.pack_forget(),
                   font=("Arial", 11)).pack(pady=(0, 15))

    tk.Label(login_frame, text="Email Password:", font=("Arial", 12)).pack(pady=(10, 10))
    password_var = tk.StringVar()
    tk.Entry(login_frame, textvariable=password_var, show="*", width=40, font=("Arial", 11)).pack(pady=(0, 10), ipady=8)
    tk.Label(login_frame, text="For Gmail, Yahoo, etc., use an App Password.", font=("Arial", 9), fg="gray").pack(
        pady=(0, 25))

    status_var = tk.StringVar()
    status_label = tk.Label(login_frame, textvariable=status_var, fg="blue")
    status_label.pack(pady=5)
    status_label.pack_forget()

    def login():
        login_button.config(state=tk.DISABLED)
        email = email_var.get().strip()
        password = password_var.get().strip()
        key_recovery = key_pass_var.get().strip()
        if not email or not password:
            messagebox.showerror("Login Error", "Enter email and password")
            login_button.config(state=tk.NORMAL)
            return
        # Require a key recovery passphrase
        if not key_recovery:
            messagebox.showerror("Login Error",
                                 "Key Recovery Passphrase is required.\nKeep it secure; it is needed every login to regenerate your unique private key.")
            login_button.config(state=tk.NORMAL)
            return
        if not is_valid_email(email):
            messagebox.showerror("Login Error", "Enter a valid email")
            login_button.config(state=tk.NORMAL)
            return

        if manual_smtp_var.get():
            smtp_server = smtp_server_var.get()
            try:
                smtp_port_val = int(smtp_port_var.get())
            except ValueError:
                messagebox.showerror("Login Error", "SMTP Port must be a number")
                login_button.config(state=tk.NORMAL)
                return
            use_ssl = use_ssl_var.get()
            if not smtp_server:
                messagebox.showerror("Login Error", "Enter SMTP server address")
                login_button.config(state=tk.NORMAL)
                return
            smtp_settings = {"smtp_server": smtp_server, "smtp_port": smtp_port_val, "use_ssl": use_ssl}
        else:
            _, smtp_settings = get_provider_settings(email)
            if not smtp_settings:
                messagebox.showerror("Login Error", "Could not detect SMTP settings. Use manual configuration.")
                manual_smtp_var.set(True)
                smtp_frame.pack(fill="x", pady=15)
                login_button.config(state=tk.NORMAL)
                return

        status_var.set("Verifying credentials...")
        status_label.pack(pady=5)
        login_window.update()

        def handle_error(err_msg):
            status_label.pack_forget()
            messagebox.showerror("Error", err_msg)
            login_button.config(state=tk.NORMAL)

        def login_thread():
            try:
                if smtp_settings["use_ssl"]:
                    with smtplib.SMTP_SSL(smtp_settings["smtp_server"], smtp_settings["smtp_port"]) as smtp:
                        smtp.login(email, password)
                else:
                    with smtplib.SMTP(smtp_settings["smtp_server"], smtp_settings["smtp_port"]) as smtp:
                        smtp.ehlo()
                        smtp.starttls()
                        smtp.ehlo()
                        smtp.login(email, password)
                status_var.set("Login successful!")
                # Load or generate RSA keys using the key recovery passphrase (which is required).
                get_rsa_key_pair(email, key_recovery)
                login_window.after(800, lambda: [login_window.destroy(),
                                                 show_main_application(email, password, smtp_settings)])
            except Exception as e:
                login_window.after(0, lambda: handle_error(str(e)))

        Thread(target=login_thread, daemon=True).start()

    login_button = tk.Button(login_frame, text="Login", command=login,
                             width=15, font=("Arial", 12, "bold"), bg="#E0B0FF", fg="white", height=2)
    login_button.pack(pady=20)

    login_window.after(200, detect_email_provider)
    # Ensure that closing the login window also deletes any local data (if desired)
    login_window.protocol("WM_DELETE_WINDOW", lambda: [login_window.destroy(),
                                                         shutil.rmtree("keys") if os.path.exists("keys") else None,
                                                         shutil.rmtree("contacts") if os.path.exists("contacts") else None])
    login_window.mainloop()


# Main application window with three tabs: Send Email, Decrypt Email, and Public Key.
def show_main_application(user_email, app_password, smtp_settings):
    root = tk.Tk()
    root.title("Secure Email Application")
    root.geometry("900x600")
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    status_frame = tk.Frame(root, bd=1, relief=tk.SUNKEN)
    status_frame.pack(side=tk.BOTTOM, fill=tk.X)
    provider_name = get_provider_name(user_email)
    tk.Label(status_frame, text=f"Logged in as: {user_email} ({provider_name})", anchor=tk.W, padx=5, pady=2).pack(
        side=tk.LEFT)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both", padx=10, pady=10)

    # ----- Send Email Tab -----
    send_frame = tk.Frame(notebook, padx=20, pady=20)
    notebook.add(send_frame, text="Send Email")
    tk.Label(send_frame, text="Recipient Email:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))
    recipient_entry = tk.Entry(send_frame, width=50, font=("Arial", 10))
    recipient_entry.pack(fill="x", pady=(5, 10))
    tk.Label(send_frame, text="Subject:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))
    subject_entry = tk.Entry(send_frame, width=50, font=("Arial", 10))
    subject_entry.pack(fill="x", pady=(5, 10))
    tk.Label(send_frame, text="Message:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))
    message_entry = tk.Text(send_frame, height=12, width=60, font=("Arial", 10))
    message_entry.pack(fill="both", expand=True, pady=(5, 15))

    def send_email():
        recipient = recipient_entry.get().strip()
        subject = subject_entry.get().strip()
        message = message_entry.get("1.0", tk.END).strip()
        if not recipient or not message:
            messagebox.showerror("Error", "Fill in all fields.")
            return
        if not is_valid_email(recipient):
            messagebox.showerror("Error", "Enter a valid recipient email.")
            return
        send_button.config(state=tk.DISABLED, text="Sending...")
        root.update()
        # Load the recipient's public key from the contacts folder when needed by send_full_secure_email
        success, msg = send_full_secure_email(message, app_password, recipient, user_email, smtp_settings)
        if success:
            messagebox.showinfo("Success", msg)
            recipient_entry.delete(0, tk.END)
            subject_entry.delete(0, tk.END)
            message_entry.delete("1.0", tk.END)
        else:
            messagebox.showerror("Error", msg)
        send_button.config(state=tk.NORMAL, text="Send Email")

    send_button = tk.Button(send_frame, text="Send Email", command=send_email,
                            height=2, font=("Arial", 11, "bold"), bg="#4CAF50", fg="white")
    send_button.pack(pady=15)

    # ----- Decrypt Email Tab -----
    decrypt_frame = tk.Frame(notebook, padx=20, pady=20)
    notebook.add(decrypt_frame, text="Decrypt Email")
    tk.Label(decrypt_frame, text="Sender Email:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))
    sender_email_entry = tk.Entry(decrypt_frame, width=50, font=("Arial", 10))
    sender_email_entry.pack(fill="x", pady=(5, 10))
    tk.Label(decrypt_frame, text="Paste Encrypted Payload:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))

    payload_frame = tk.Frame(decrypt_frame)
    payload_frame.pack(fill="both", expand=True, pady=(5, 15))
    payload_scroll = tk.Scrollbar(payload_frame)
    payload_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    payload_text = tk.Text(payload_frame, height=12, width=70, font=("Arial", 10), yscrollcommand=payload_scroll.set)
    payload_text.pack(side=tk.LEFT, fill="both", expand=True)
    payload_scroll.config(command=payload_text.yview)

    def decrypt_email():
        try:
            decrypt_button.config(state=tk.DISABLED, text="Decrypting...")
            root.update()
            safe_email = user_email.replace("@", "_at_").replace(".", "_")
            key_path = f"keys/{safe_email}_private.pem"
            with open(key_path, "rb") as f:
                receiver_private_key = serialization.load_pem_private_key(f.read(), password=None)
            sender_input = sender_email_entry.get().strip()
            from contacts_manager import retrieve_public_key
            sender_public_pem = retrieve_public_key(sender_input)
            if not sender_public_pem:
                messagebox.showerror("Error", "Sender's public key not found in contacts.")
                decrypt_button.config(state=tk.NORMAL, text="Decrypt & Verify")
                return
            sender_public_key = serialization.load_pem_public_key(sender_public_pem.encode())
            payload = json.loads(payload_text.get("1.0", tk.END).strip())
            encrypted_msg = base64.b64decode(payload["encrypted_message"])
            encrypted_key = base64.b64decode(payload["encrypted_key"])
            signature = base64.b64decode(payload["signature"])
            aes_key = rsa_decrypt_key(encrypted_key, receiver_private_key)
            decrypted_msg = aes_decrypt(encrypted_msg, aes_key)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(decrypted_msg.encode())
            hashed_msg = digest.finalize()
            if verify_signature(hashed_msg, signature, sender_public_key):
                result_box.config(state=tk.NORMAL)
                result_box.delete("1.0", tk.END)
                result_box.insert(tk.END, decrypted_msg)
                result_box.config(state=tk.DISABLED)
                messagebox.showinfo("Success", "Decryption and verification successful.")
            else:
                messagebox.showerror("Error", "Signature verification failed!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
        finally:
            decrypt_button.config(state=tk.NORMAL, text="Decrypt & Verify")

    decrypt_button = tk.Button(decrypt_frame, text="Decrypt & Verify", command=decrypt_email,
                               height=2, font=("Arial", 11, "bold"), bg="#E0B0FF", fg="white")
    decrypt_button.pack(pady=10)
    tk.Label(decrypt_frame, text="Decrypted Message:", font=("Arial", 12)).pack(anchor="w")
    result_frame = tk.Frame(decrypt_frame)
    result_frame.pack(fill="both", expand=True, pady=(5, 10))
    result_scroll = tk.Scrollbar(result_frame)
    result_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    result_box = tk.Text(result_frame, height=8, width=70, font=("Arial", 11), yscrollcommand=result_scroll.set)
    result_box.pack(side=tk.LEFT, fill="both", expand=True)
    result_scroll.config(command=result_box.yview)

    # ----- Public Key Tab -----
    pk_frame = tk.Frame(notebook, padx=20, pady=20)
    notebook.add(pk_frame, text="Public Key")
    safe_email = user_email.replace("@", "_at_").replace(".", "_")
    public_key_path = f"keys/{safe_email}_public.pem"
    try:
        with open(public_key_path, "r") as f:
            my_public_key = f.read()
    except Exception as e:
        my_public_key = "Error loading public key."

    filtered_lines = [line for line in my_public_key.splitlines() if not line.startswith("-----")]
    display_key = "\n".join(filtered_lines)

    tk.Label(pk_frame, text="Your Public Key:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
    pk_box = tk.Text(pk_frame, height=8, width=80)
    pk_box.insert(tk.END, display_key)
    pk_box.config(state=tk.DISABLED)
    pk_box.pack(pady=(0, 10))

    tk.Label(pk_frame, text="Send your Public Key:", font=("Arial", 12)).pack(anchor="w", pady=(10, 0))
    tk.Label(pk_frame, text="Recipient Email:", font=("Arial", 10)).pack(anchor="w")
    pk_recipient_entry = tk.Entry(pk_frame, width=40, font=("Arial", 10))
    pk_recipient_entry.pack(pady=(0, 5))

    def send_my_public_key():
        recipient = pk_recipient_entry.get().strip()
        if not recipient or not is_valid_email(recipient):
            messagebox.showerror("Error", "Enter a valid recipient email.")
            return
        from network import send_secure_email
        try:
            send_secure_email("My Public Key", my_public_key, user_email, app_password, recipient, smtp_settings)
            messagebox.showinfo("Success", "Public key sent successfully.")
            pk_recipient_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send public key:\n{e}")

    tk.Button(pk_frame, text="Send Public Key", command=send_my_public_key, font=("Arial", 10, "bold")).pack(
        pady=(0, 10))

    tk.Label(pk_frame, text="Update Contact (Paste received Public Key):", font=("Arial", 12)).pack(anchor="w",
                                                                                                    pady=(10, 0))
    tk.Label(pk_frame, text="Contact Email:", font=("Arial", 10)).pack(anchor="w")
    contact_email_entry = tk.Entry(pk_frame, width=40, font=("Arial", 10))
    contact_email_entry.pack(pady=(0, 5))
    tk.Label(pk_frame, text="Paste Public Key:", font=("Arial", 10)).pack(anchor="w")
    contact_pk_text = tk.Text(pk_frame, height=5, width=80, font=("Arial", 10))
    contact_pk_text.pack(pady=(0, 10))

    def update_contact_pk():
        contact_email = contact_email_entry.get().strip()
        contact_pk = contact_pk_text.get("1.0", tk.END).strip()

        if not contact_email or not contact_pk:
            messagebox.showerror("Error", "Fill in both contact email and public key.")
            return

        # Store the contact's public key locally
        from contacts_manager import store_public_key
        store_public_key(contact_email, contact_pk)
        messagebox.showinfo("Success", "Contact updated successfully.")

        # Automatically send YOUR public key back to this contact
        try:
            safe_email = user_email.replace("@", "_at_").replace(".", "_")
            public_key_path = f"keys/{safe_email}_public.pem"
            with open(public_key_path, "r") as f:
                local_public_key = f.read()
            from network import send_secure_email
            send_secure_email("My Public Key", local_public_key, user_email, app_password, contact_email, smtp_settings)
            messagebox.showinfo("Success", "Your public key has been sent to the contact.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send your public key:\n{e}")

        contact_email_entry.delete(0, tk.END)
        contact_pk_text.delete("1.0", tk.END)

    tk.Button(pk_frame, text="Update Contact", command=update_contact_pk, font=("Arial", 10, "bold")).pack(pady=(0, 10))

    def remove_readonly_attr(folder):
        for root, dirs, files in os.walk(folder):
            for d in dirs:
                dir_path = os.path.join(root, d)
                os.chmod(dir_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            for f in files:
                file_path = os.path.join(root, f)
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
        os.chmod(folder, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)


    # Define a unified cleanup function to delete local keys and contacts before closing
    def cleanup_and_exit(root):
        errors = []
        for folder in ["keys", "contacts"]:
            try:
                if os.path.exists(folder):
                    remove_readonly_attr(folder)
                    shutil.rmtree(folder)
            except Exception as e:
                errors.append(f"{folder}: {e}")
        if errors:
            messagebox.showerror("Error", "Failed to delete local data:\n" + "\n".join(errors))
        root.destroy()


    # Logout button: calls cleanup, then returns to login screen
    def logout():
        cleanup_and_exit(root)
        run_gui()

    tk.Button(status_frame, text="Logout", command=logout).pack(side=tk.RIGHT, padx=5, pady=2)
    # When the user closes the main application window, run cleanup as well.
    root.protocol("WM_DELETE_WINDOW", cleanup_and_exit)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
