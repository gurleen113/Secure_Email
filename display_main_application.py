import tkinter as tk
from tkinter import ttk, messagebox
import json
from utils import delete_directory
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from CryptoHandler import CryptoHandler
from Signer import Signer
from ContactManager import ContactManager
from EmailProvider import EmailProvider
from EmailService import EmailService
from PKIManager import PKIManager
from utils import is_valid_email, center_window, confirm_exit, set_window_icon

def display_main_application(user_email, app_password, smtp_settings):
    root = tk.Tk()
    root.title("Secure Email Application")
    
    # Set the window icon
    set_window_icon(root)
    
    # Start with a reasonable default size, but allow resizing
    root.geometry("800x650")
    root.minsize(750, 600)  # Set minimum window size
    
    # Allow the window to be resized by the user
    root.resizable(True, True)

    crypto   = CryptoHandler()
    signer   = Signer()
    contacts = ContactManager()
    provider = EmailProvider()
    service  = EmailService()

    def get_contact_list():
        return [
            s.replace("_at_", "@").replace("_", ".")
            for s in contacts.load_contacts().keys()
        ]

    safe = PKIManager._safe_email(user_email)
    with open(f"keys/{safe}_public.pem") as f:
        full_pem = f.read()
    stripped_pem = "\n".join(
        line for line in full_pem.splitlines()
        if not (line.startswith("-----BEGIN") or line.startswith("-----END"))
    )

    status_frame = tk.Frame(root, bd=1, relief=tk.SUNKEN)
    status_frame.pack(side=tk.BOTTOM, fill=tk.X)
    pname = provider.get_provider_name(user_email)
    tk.Label(status_frame,
             text=f"Logged in as: {user_email} ({pname})",
             anchor=tk.W, padx=5, pady=2).pack(side=tk.LEFT)
    
    def logout_and_run_gui():
        try:
            delete_directory("keys")
            delete_directory("contacts")
        except Exception as e:
            print(f"Error during logout cleanup: {e}")

        root.destroy()
        from run_gui import run_gui
        run_gui()
        
    tk.Button(status_frame, text="Logout", command=logout_and_run_gui).pack(side=tk.RIGHT, padx=5, pady=2)

    nb = ttk.Notebook(root)
    nb.pack(expand=True, fill="both", padx=10, pady=10)
    
    # Function to calculate the optimal window size based on content
    def resize_window_on_tab_change(event):
        # Get the notebook (parent of the tab)
        notebook = event.widget
        
        # Get current width
        current_width = root.winfo_width()
        
        # For the About tab, we need a taller window
        if notebook.select() == notebook.tabs()[3]:  # About tab (index 3)
            # Resize to fit About tab content
            root.geometry(f"{current_width}x850")  # Increased height to accommodate all content
        else:
            # For other tabs, a smaller height is sufficient
            root.geometry(f"{current_width}x650")
    
    # Bind tab change event to resize function
    nb.bind("<<NotebookTabChanged>>", resize_window_on_tab_change)

    # Send Email Tab
    send_f = tk.Frame(nb, padx=20, pady=20)
    nb.add(send_f, text="Send Email")
    tk.Label(send_f, text="Recipient Email:", font=("Arial",12)).pack(anchor="w")
    recipient_var = tk.StringVar()
    recipient_cb = ttk.Combobox(
        send_f, textvariable=recipient_var,
        values=get_contact_list(),
        font=("Arial",10), width=48
    )
    recipient_cb.pack(fill="x", pady=5)
    tk.Label(send_f, text="Subject:", font=("Arial",12)).pack(anchor="w", pady=(10,0))
    subject_entry = tk.Entry(send_f, font=("Arial",10), width=60)
    subject_entry.pack(fill="x", pady=5)
    tk.Label(send_f, text="Message:", font=("Arial",12)).pack(anchor="w")
    msg_txt = tk.Text(send_f, height=10, font=("Arial",10))
    msg_txt.pack(fill="both", expand=True, pady=5)

    def send_email():
        r = recipient_var.get().strip()
        sub = subject_entry.get().strip()
        m = msg_txt.get("1.0", tk.END).strip()
        if not r or not m:
            messagebox.showerror("Error","Fill in all fields.")
            return
        # Format the subject line appropriately
        email_subject = f"{sub} - Secure Email" if sub else "Secure Email"
        ok, info = service.send_full_secure_email(
            m, app_password, r, user_email, smtp_settings, 
            subject=email_subject
        )
        if ok:
            messagebox.showinfo("Success", info)
            subject_entry.delete(0, tk.END)
            msg_txt.delete("1.0", tk.END)
        else:
            messagebox.showerror("Error", info)
    send_btn = tk.Button(send_f, text="Send Email",
                         font=("Arial",11,"bold"), bg="#4CAF50", fg="white",
                         command=send_email)
    send_btn.pack(pady=10)

    # Decrypt Email Tab
    dec_f = tk.Frame(nb, padx=20, pady=20)
    nb.add(dec_f, text="Decrypt Email")
    tk.Label(dec_f, text="Sender Email:", font=("Arial",12)).pack(anchor="w")
    sender_var = tk.StringVar()
    sender_cb = ttk.Combobox(
        dec_f, textvariable=sender_var,
        values=get_contact_list(),
        font=("Arial",10), width=48
    )
    sender_cb.pack(fill="x", pady=5)
    tk.Label(dec_f, text="Paste Encrypted Payload:", font=("Arial",12)).pack(anchor="w")
    payload_txt = tk.Text(dec_f, height=10, font=("Arial",10))
    payload_txt.pack(fill="both", expand=True, pady=5)
    tk.Label(dec_f, text="Decrypted Message:", font=("Arial",12)).pack(anchor="w", pady=(10,0))
    result_txt = tk.Text(dec_f, height=8, font=("Arial",10), state=tk.DISABLED)
    result_txt.pack(fill="both", expand=True, pady=5)

    def decrypt_email():
        # Validate sender first
        sender = sender_var.get().strip()
        if not sender:
            messagebox.showerror("Validation Error", "Please select or enter a sender email address")
            return
            
        # Check if we have the sender's public key
        spem = contacts.retrieve_public_key(sender)
        if not spem:
            messagebox.showerror("Key Error", f"No public key found for {sender}. Please make sure you have exchanged keys.")
            return
            
        # Get the payload
        raw = payload_txt.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showerror("Validation Error", "Please paste the encrypted payload")
            return
            
        try:
            # Load private key
            try:
                priv_key = PKIManager.load_private_key(f"keys/{safe}_private.pem")
            except Exception as e:
                messagebox.showerror("Key Error", f"Could not load your private key: {str(e)}")
                return
                
            # Parse the payload
            try:
                pl = json.loads(raw)
            except json.JSONDecodeError:
                messagebox.showerror("Format Error", "Invalid payload format. The message appears to have been altered or corrupted.")
                return
                
            # Extract encrypted data based on format
            try:
                if isinstance(pl, list) and len(pl) == 3:
                    # New format (array)
                    em = base64.b64decode(pl[0])  # encrypted_message
                    ek = base64.b64decode(pl[1])  # encrypted_key
                    sig = base64.b64decode(pl[2])  # signature
                else:
                    messagebox.showerror("Format Error", 
                        "The message format is invalid. It appears the message may have been altered or corrupted.")
                    return
            except base64.binascii.Error:
                messagebox.showerror("Message Integrity Error", 
                    "The encrypted message appears to have been altered or corrupted. " +
                    "Base64 decoding failed due to invalid characters.")
                return
            except Exception as e:
                messagebox.showerror("Decode Error", "The message appears to have been altered or corrupted.")
                return
                
            # Decrypt the AES key with RSA
            try:
                aesk = crypto.rsa_decrypt_key(ek, priv_key)
            except Exception as e:
                messagebox.showerror("Decryption Error", 
                    "Failed to decrypt the message key. The message may have been altered " +
                    "or was not encrypted for you.")
                return
                
            # Decrypt the message with AES
            try:
                msg = crypto.aes_decrypt(em, aesk)
            except Exception as e:
                messagebox.showerror("Decryption Error", 
                    "Failed to decrypt the message content. The message appears to have been altered or corrupted.")
                return
                
            # Load sender's public key for verification
            try:
                spub = serialization.load_pem_public_key(spem.encode())
            except Exception as e:
                messagebox.showerror("Key Error", f"Could not load sender's public key: {str(e)}")
                return
                
            # Verify signature
            try:
                digest = hashes.Hash(hashes.SHA256())
                digest.update(msg.encode())
                if not signer.verify_signature(spub, digest.finalize(), sig):
                    messagebox.showerror("Verification Error", 
                        "Signature verification failed! The message has been altered or tampered with.")
                    return
            except Exception as e:
                messagebox.showerror("Verification Error", "Signature verification failed. The message may have been altered.")
                return
                
            # Success! Display the decrypted message
            result_txt.config(state=tk.NORMAL)
            result_txt.delete("1.0", tk.END)
            result_txt.insert(tk.END, msg)
            result_txt.config(state=tk.DISABLED)
            messagebox.showinfo("Success", "Message decrypted and verified successfully")
                
        except Exception as e:
            # Catch-all for any other unexpected errors
            messagebox.showerror("Unexpected Error", "An error occurred during decryption. The message may have been altered.")
            return

    dec_btn = tk.Button(dec_f, text="Decrypt & Verify",
                        font=("Arial",11,"bold"), bg="#E0B0FF", fg="white",
                        command=decrypt_email)
    dec_btn.pack(pady=10)

    # Public Key Tab
    pk_f = tk.Frame(nb, padx=20, pady=20)
    nb.add(pk_f, text="Public Key")
    tk.Label(pk_f, text="Your Public Key:", font=("Arial",12,"bold")).pack(anchor="w")
    display_box = tk.Text(pk_f, height=8, font=("Arial",10))
    display_box.insert(tk.END, stripped_pem)
    display_box.config(state=tk.DISABLED)
    display_box.pack(fill="both", expand=True, pady=5)

    # Send Public Key
    tk.Label(pk_f, text="Send your Public Key:", font=("Arial",12)).pack(anchor="w", pady=(10,0))
    tk.Label(pk_f, text="Recipient Email:", font=("Arial",10)).pack(anchor="w")
    sendpk_var = tk.StringVar()
    sendpk_entry = tk.Entry(pk_f, textvariable=sendpk_var,
                             width=48, font=("Arial",10))
    sendpk_entry.pack(fill="x", pady=5)
    def send_public_key():
        rc = sendpk_var.get().strip()
        if not rc or not is_valid_email(rc):
            messagebox.showerror("Error","Enter a valid recipient email.")
            return
        service.send_secure_email("My Public Key", stripped_pem,
                                  user_email, app_password, rc, smtp_settings)
        messagebox.showinfo("Success","Public key sent.")
        sendpk_entry.delete(0, tk.END)
    tk.Button(pk_f, text="Send Public Key", command=send_public_key,fg="white",bg="green",
              font=("Arial",10,"bold")).pack(pady=(0,10))

    # Update Contact
    tk.Label(pk_f, text="Update Contact (Paste received Public Key):",
             font=("Arial",12)).pack(anchor="w", pady=(10,0))
    tk.Label(pk_f, text="Contact Email:", font=("Arial",10)).pack(anchor="w")
    upd_var = tk.StringVar()
    upd_entry = tk.Entry(pk_f, textvariable=upd_var,
                          width=48, font=("Arial",10))
    upd_entry.pack(pady=5)
    pk_text = tk.Text(pk_f, height=5, font=("Arial",10))
    pk_text.pack(fill="both", expand=True, pady=5)
    
    def update_contact():
        try:
            ce = upd_var.get().strip()
            if not ce or not is_valid_email(ce):
                messagebox.showerror("Error", "Enter a valid contact email.")
                return
                
            body = pk_text.get("1.0", tk.END).strip()
            if not body:
                messagebox.showerror("Error", "Paste the received public key.")
                return
                
            full = "-----BEGIN PUBLIC KEY-----\n"+body+"\n-----END PUBLIC KEY-----\n"
            
            # Check if this is a new contact or if the key has changed
            should_send_key = False
            existing_key = contacts.retrieve_public_key(ce)
            
            if not existing_key:
                # This is a new contact
                should_send_key = True
                message = "Contact saved. Sending your public key as a response."
            elif existing_key.strip() != full.strip():
                # The key is different from what we have stored
                should_send_key = True
                message = "Contact updated with new key. Sending your public key as a response."
            else:
                # The key is the same as what we already have
                message = "Contact saved. Key is unchanged, no need to resend your public key."
                
            # Save the contact's key
            contacts.store_public_key(ce, full)
            
            # Send your public key if needed
            if should_send_key:
                # Get your public key
                with open(f"keys/{safe}_public.pem") as f:
                    my_full_pem = f.read()
                
                my_stripped_pem = "\n".join(
                    line for line in my_full_pem.splitlines()
                    if not (line.startswith("-----BEGIN") or line.startswith("-----END"))
                )
                
                # Send your public key
                try:
                    service.send_secure_email(
                        "My Public Key",
                        my_stripped_pem,
                        user_email,
                        app_password,
                        ce,
                        smtp_settings
                    )
                except Exception as e:
                    messagebox.showinfo(
                        "Partial Success", 
                        f"Contact saved, but couldn't send your public key: {str(e)}"
                    )
                    # Continue execution, we still want to update the UI
            
            messagebox.showinfo("Success", message)
            
            # Update the contact lists in the comboboxes
            contact_list = get_contact_list()
            recipient_cb['values'] = contact_list
            sender_cb['values'] = contact_list
            
            # Clear the input fields
            upd_var.set("")
            pk_text.delete("1.0", tk.END)
        except Exception as e:
            print(f"Error updating contact: {e}")
            messagebox.showerror("Error", f"Failed to update contact: {e}")
            
    tk.Button(pk_f, text="Update Contact", command=update_contact,fg="white",bg="green",
              font=("Arial",10,"bold")).pack(pady=(0,10))

    # About Tab - simpler implementation without scrolling
    about_f = tk.Frame(nb, padx=20, pady=20)
    nb.add(about_f, text="About")

    # App title
    tk.Label(about_f, text="Secure Email Application", 
             font=("Arial", 16, "bold")).pack(pady=(0,10))

    # Version info
    tk.Label(about_f, text="Version 7.0.0", 
             font=("Arial", 10, "italic")).pack(pady=(0,20))

    # Description text - using a Label for better automatic sizing
    description = tk.Label(about_f, 
                          justify=tk.LEFT,
                          anchor="w",
                          wraplength=750,  # Adjust this based on your window width
                          font=("Arial", 10), 
                          bg=about_f.cget("background"))
    description.pack(fill="both", expand=True, anchor="w")

    # About content
    about_content = """
This secure email application provides end-to-end encryption for your email communications:

• RSA Public/Private Key Encryption: Each user has their own unique key pair. Your private key never leaves your device.

• AES Symmetric Encryption: Messages are encrypted with a fast AES cipher, and the key for each message is protected by RSA encryption.

• Digital Signatures: Every message is digitally signed to verify the sender's identity and ensure message integrity.

• User-Friendly: The application is designed to be easy to use, with a simple interface for sending and receiving encrypted messages. 

• Contact Management: The application includes a contact manager for easy access to your contacts' public keys.

• Custom SMTP Support: Users can configure custom SMTP settings for sending emails, making it flexible for different email providers.

• Error Handling: The application includes error handling for common issues, such as invalid email addresses and decryption errors.

• Secure Key Storage: Private keys are securely stored on the user's device, ensuring that they are not exposed to third parties.

• Message Integrity: The application verifies the integrity of messages using cryptographic hashes, ensuring that messages have not been altered in transit.

How It Works:
1. Exchange public keys with your contacts on the Public Key tab
2. Compose your message in the Send Email tab
3. The message is automatically encrypted with the recipient's public key
4. Only the recipient can decrypt it with their private key
    """

    description.config(text=about_content)

    # Add a horizontal line
    tk.Frame(about_f, height=1, bg="gray").pack(fill="x", pady=10)

    # Credits - ensure correct attribution
    tk.Label(about_f, text="Created by Gurleen Sahota", 
             font=("Arial", 9), fg="gray").pack(pady=5)

    # Use the confirm_exit function from utils.py for window close handling
    root.protocol("WM_DELETE_WINDOW", lambda: confirm_exit(root))
    
    center_window(root)
    root.mainloop()