import tkinter as tk
from utils import center_window, confirm_exit, set_window_icon
from show_login_page import display_login_form  


def run_gui():
    option_window = tk.Tk()
    option_window.title("Secure Email Application")
    
    # Set the window icon
    set_window_icon(option_window)
    
    main_frame = tk.Frame(option_window, padx=30, pady=30)
    main_frame.pack(expand=True, fill="both")
    tk.Label(main_frame, text="Secure Email Application",
             font=("Arial",16,"bold")).pack(pady=(0,20))
    tk.Button(main_frame, text="Login", command=lambda:[option_window.destroy(), display_login_form()],
              width=20, height=2, font=("Arial",11,"bold"),
              bg="#008000", fg="white").pack()
    center_window(option_window)
    
    # When closing option window, show confirmation dialog
    option_window.protocol("WM_DELETE_WINDOW", lambda: confirm_exit(option_window))
    
    option_window.mainloop()

if __name__ == "__main__":
    run_gui()