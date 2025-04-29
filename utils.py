import re
import os
import sys
from tkinter import messagebox

def is_valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email) is not None

def center_window(window):
    window.update_idletasks()
    w, h = window.winfo_reqwidth(), window.winfo_reqheight()
    x = (window.winfo_screenwidth()  - w) // 2
    y = (window.winfo_screenheight() - h) // 2
    window.geometry(f"{w}x{h}+{x}+{y}")

def set_window_icon(window):
    try:
        ico_path = os.path.join(os.path.dirname(__file__), "config", "icon.ico")
        if os.path.exists(ico_path):
            window.iconbitmap(ico_path)
            print(f"Window icon set from {ico_path}")
        else:
            print(f"Icon file not found at {ico_path}")
    except Exception as e:
        print(f"Error setting window icon: {e}")

def delete_directory(directory_path):
    if os.path.exists(directory_path):
        for root, dirs, files in os.walk(directory_path, topdown=False):
            for file in files:
                try:
                    os.remove(os.path.join(root, file))
                except Exception as e:
                    print(f"Error deleting file {file}: {e}")
            for dir in dirs:
                try:
                    os.rmdir(os.path.join(root, dir))
                except Exception as e:
                    print(f"Error deleting directory {dir}: {e}")
        try:
            os.rmdir(directory_path)
        except Exception as e:
            print(f"Error deleting root directory {directory_path}: {e}")

def confirm_exit(window):
    if messagebox.askyesno("Exit Application", "Are you sure you want to exit the application?", icon='warning'):
        try:
            delete_directory("keys")
            delete_directory("contacts")
        except Exception as e:
            print(f"Error during cleanup: {e}")
        window.destroy()
        try:
            sys.exit()
        except SystemExit:
            pass