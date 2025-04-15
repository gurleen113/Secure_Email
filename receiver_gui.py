import tkinter as tk
from tkinter import messagebox
import json, base64
from cryptography.hazmat.primitives import serialization, hashes
from src.encryption import aes_decrypt, rsa_decrypt_key
from src.hashing_signature import verify_signature

def load_key(path, is_private):
    with open(path, "rb") as key_file:
        return (serialization.load_pem_private_key(key_file.read(), password=None)
                if is_private
                else serialization.load_pem_public_key(key_file.read()))

def run_receiver_gui():
    root = tk.Tk()
    root.title("Receiver - Decrypt & Verify Secure Email")
    tk.Label(root, text="Paste Encrypted Email Payload Below:").pack()
    payload_text = tk.Text(root, height=15, width=80)
    payload_text.pack()
    def decrypt_and_verify():
        try:
            receiver_private_key = load_key("keys/receiver_private.pem", True)
            payload = json.loads(payload_text.get("1.0", tk.END).strip())
            encrypted_msg = base64.b64decode(payload["encrypted_message"])
            encrypted_key = base64.b64decode(payload["encrypted_key"])
            signature = base64.b64decode(payload["signature"])
            sender_public_key_pem = payload["sender_public_key"].encode()
            sender_public_key = serialization.load_pem_public_key(sender_public_key_pem)
            aes_key = rsa_decrypt_key(encrypted_key, receiver_private_key)
            decrypted_msg = aes_decrypt(encrypted_msg, aes_key)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(decrypted_msg.encode())
            hashed_msg = digest.finalize()
            if verify_signature(hashed_msg, signature, sender_public_key):
                result_box.delete("1.0", tk.END)
                result_box.insert(tk.END, decrypted_msg)
                messagebox.showinfo("✅ Success", "Signature Verified. Message is authentic.")
            else:
                messagebox.showerror("❌ Warning", "Signature verification failed!")
        except Exception as e:
            messagebox.showerror("Error", f"Something went wrong:\n{e}")
    tk.Button(root, text="Decrypt & Verify", command=decrypt_and_verify).pack(pady=10)
    tk.Label(root, text="Decrypted Message:").pack()
    result_box = tk.Text(root, height=10, width=80)
    result_box.pack()
    root.mainloop()

if __name__ == "__main__":
    run_receiver_gui()
