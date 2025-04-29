import tkinter as tk
from EmailProvider import EmailProvider
import smtplib
import ssl
from threading import Thread
from tkinter import messagebox
from PKIManager import PKIManager
from utils import center_window, is_valid_email, confirm_exit, set_window_icon


def display_login_form():
    login_window = tk.Tk()
    login_window.title("Login - Secure Email")

    # Set the window icon
    set_window_icon(login_window)

    frame = tk.Frame(login_window, padx=20, pady=20)
    frame.pack(expand=True, fill="both")

    provider = EmailProvider()

    def go_back():
        login_window.destroy()
        # Import here to avoid circular imports
        from run_gui import run_gui
        run_gui()

    tk.Button(frame, text="← Back", command=go_back, anchor="w").pack(anchor="w", pady=(0, 15))
    tk.Label(frame, text="Login to Secure Email", font=("Arial", 16, "bold")).pack(pady=(0, 5))
    provider_label = tk.Label(frame, text="", font=("Arial", 10), fg="blue")
    provider_label.pack(pady=(0, 20))

    tk.Label(frame, text="Email Address:", font=("Arial", 12)).pack(anchor="w")
    email_var = tk.StringVar()
    email_entry = tk.Entry(frame, textvariable=email_var, width=40, font=("Arial", 11))
    email_entry.pack(pady=5, ipady=6)

    manual_var = tk.BooleanVar(value=False)
    smtp_frame = tk.LabelFrame(frame, text="SMTP Server Settings",
                               padx=15, pady=15)
    server_var = tk.StringVar()
    port_var = tk.StringVar(value="465")
    ssl_var = tk.BooleanVar(value=True)
    tk.Label(smtp_frame, text="SMTP Server:", font=("Arial", 11)) \
        .grid(row=0, column=0, sticky="w", pady=8)
    tk.Entry(smtp_frame, textvariable=server_var,
             width=30, font=("Arial", 11)) \
        .grid(row=0, column=1, pady=8)
    tk.Label(smtp_frame, text="SMTP Port:", font=("Arial", 11)) \
        .grid(row=1, column=0, sticky="w", pady=8)
    tk.Entry(smtp_frame, textvariable=port_var,
             width=10, font=("Arial", 11)) \
        .grid(row=1, column=1, sticky="w", pady=8)
    tk.Checkbutton(smtp_frame, text="Use SSL", variable=ssl_var,
                   font=("Arial", 11)) \
        .grid(row=2, column=0, columnspan=2, sticky="w", pady=8)

    def toggle_smtp():
        if manual_var.get():
            smtp_frame.pack(fill="x", pady=15)
        else:
            smtp_frame.pack_forget()
        login_window.update_idletasks()
        login_window.geometry(f"{login_window.winfo_reqwidth()}x{login_window.winfo_reqheight()}")

    tk.Checkbutton(frame,
                   text="Manually configure SMTP settings",
                   variable=manual_var,
                   command=toggle_smtp,
                   font=("Arial", 11)) \
        .pack(pady=(0, 15))

    tk.Label(frame, text="Email Password:", font=("Arial", 12)) \
        .pack(anchor="w", pady=(10, 0))
    password_var = tk.StringVar()
    tk.Entry(frame, textvariable=password_var,
             show="*", width=40, font=("Arial", 11)) \
        .pack(pady=5, ipady=6)

    status_var = tk.StringVar()
    status_label = tk.Label(frame, textvariable=status_var, fg="blue")

    def detect_provider(event=None):
        email = email_var.get().strip()
        if not is_valid_email(email):
            provider_label.config(text="Enter a valid email")
            return
        pid, cfg = provider.get_provider_settings(email)
        name = provider.get_provider_name(email)
        if cfg:
            provider_label.config(text=f"Detected: {name}")
            server_var.set(cfg["smtp_server"])
            port_var.set(str(cfg["smtp_port"]))
            ssl_var.set(cfg["use_ssl"])
        else:
            provider_label.config(text=f"Provider: {name} - Manual SMTP required")

    email_entry.bind("<FocusOut>", detect_provider)
    email_entry.bind("<KeyRelease>",
                     lambda e: login_window.after(300, detect_provider)
                     )

    def login():
        status_label.pack(pady=5)
        status_var.set("Verifying credentials…")
        login_window.update()
        email = email_var.get().strip()
        password = password_var.get().strip()

        if not email or not password:
            messagebox.showerror("Login Error", "Enter email and password.")
            if login_window.winfo_exists():
                status_label.pack_forget()
            return
        if not is_valid_email(email):
            messagebox.showerror("Login Error", "Enter a valid email.")
            if login_window.winfo_exists():
                status_label.pack_forget()
            return
        if manual_var.get():
            try:
                smtp_settings = {
                    "smtp_server": server_var.get().strip(),
                    "smtp_port": int(port_var.get().strip()),
                    "use_ssl": ssl_var.get()
                }
            except ValueError:
                messagebox.showerror("Login Error", "SMTP Port must be numeric.")
                if login_window.winfo_exists():
                    status_label.pack_forget()
                return
        else:
            _, smtp_settings = provider.get_provider_settings(email)
            if not smtp_settings:
                messagebox.showerror(
                    "Login Error",
                    "Could not detect SMTP settings; please configure manually."
                )
                manual_var.set(True)
                toggle_smtp()
                if login_window.winfo_exists():
                    status_label.pack_forget()
                return

        def handle_error(error_msg):
            # Check if window still exists before attempting to modify widgets
            if login_window.winfo_exists():
                status_label.pack_forget()

            # Check for common authentication errors
            if "authentication failed" in error_msg.lower() or "auth" in error_msg.lower():
                messagebox.showerror("Login Error",
                                     "Invalid email or password. Please check your credentials and try again.")
            elif "connection" in error_msg.lower() or "network" in error_msg.lower():
                messagebox.showerror("Connection Error",
                                     "Could not connect to email server. Please check your internet connection or SMTP settings.")
            else:
                # Generic error message for other issues
                messagebox.showerror("Login Error", f"Login failed: {error_msg}")

        def helper():
            try:
                if smtp_settings["use_ssl"]:
                    with smtplib.SMTP_SSL(smtp_settings["smtp_server"],
                                          smtp_settings["smtp_port"]) as s:
                        s.login(email, password)
                else:
                    with smtplib.SMTP(smtp_settings["smtp_server"],
                                      smtp_settings["smtp_port"]) as s:
                        s.ehlo()
                        s.starttls(context=ssl.create_default_context())
                        s.ehlo()
                        s.login(email, password)

                # Check if window still exists before updating UI
                if login_window.winfo_exists():
                    status_label.config(text="Login successful!")

                # Generate RSA key pair without the key recovery passphrase
                PKIManager().get_rsa_key_pair(email)

                def proceed():
                    # Check if window still exists before destroying it
                    if login_window.winfo_exists():
                        login_window.destroy()
                        from display_main_application import display_main_application
                        display_main_application(email, password, smtp_settings)

                login_window.after(500, proceed)
            except Exception as e:
                error_message = "Wrong Email or Password"
                # Use after to ensure we're back on main thread when interacting with Tkinter
                if login_window.winfo_exists():
                    login_window.after(0, lambda: handle_error(error_message))

        Thread(target=helper, daemon=True).start()

    tk.Button(frame, text="Login", command=login,
              width=15, height=2, font=("Arial", 12, "bold"),
              bg="#E0B0FF", fg="white") \
        .pack(pady=20)

    center_window(login_window)

    # Use the confirm_exit function from utils.py to handle closing the window
    login_window.protocol("WM_DELETE_WINDOW", lambda: confirm_exit(login_window))

    login_window.mainloop()