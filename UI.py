
import tkinter as tk
from tkinter import ttk
import threading
from security import analyze_password, check_pwned_password



class PasswordCheckerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Strength Checker By Mueed Khan")

        # Window size
        self.root.geometry("390x420")
        self.root.resizable(True, True)

        # Label and entry field
        tk.Label(self.root, text="Enter your password:").pack(pady=10)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.root, textvariable=self.password_var, width=40)
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<KeyRelease>", self.on_password_change)

        # Strength progress bar
        self.progress = ttk.Progressbar(self.root, length=300, mode="determinate", maximum=4)
        self.progress.pack(pady=10)

        # Labels for results
        self.strength_label = tk.Label(self.root, text="Strength: ")
        self.strength_label.pack(pady=5)

        self.crack_time_label = tk.Label(self.root, text="Crack time: ")
        self.crack_time_label.pack(pady=5)

        self.suggestions_label = tk.Label(self.root, text="Suggestions: ")
        self.suggestions_label.pack(pady=5)

        self.pwned_label = tk.Label(self.root, text="Pwned status: ")
        self.pwned_label.pack(pady=5)

        # Disclaimer
        disclaimer_text = "Your password never leaves your device."
        tk.Label(self.root, text=disclaimer_text, fg="gray", wraplength=400).pack(side="bottom", pady=10)

        # Debounce variables
        self.last_change_id = None

    def on_password_change(self, event=None):
        """Trigger analysis after 500ms pause (debouncing)."""
        if self.last_change_id:
            self.root.after_cancel(self.last_change_id)

        self.last_change_id = self.root.after(500, self.update_analysis)

    def update_analysis(self):
        """Run zxcvbn + HIBP check."""
        password = self.password_var.get()

        if not password:
            # Reset UI when empty
            self.progress["value"] = 0
            self.strength_label.config(text="Strength: ")
            self.crack_time_label.config(text="Crack time: ")
            self.suggestions_label.config(text="Suggestions: ")
            self.pwned_label.config(text="Pwned status: ")
            return

        # --- Strength Analysis ---
        result = analyze_password(password)

        score = result["score"]
        strength_text = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
        self.progress["value"] = score
        # Change color by style
        style = ttk.Style()
        if score <= 1:
            style.configure("red.Horizontal.TProgressbar", foreground="red", background="red")
            self.progress["style"] = "red.Horizontal.TProgressbar"
        elif score == 2:
            style.configure("orange.Horizontal.TProgressbar", foreground="orange", background="orange")
            self.progress["style"] = "orange.Horizontal.TProgressbar"
        else:
            style.configure("green.Horizontal.TProgressbar", foreground="green", background="green")
            self.progress["style"] = "green.Horizontal.TProgressbar"

        self.strength_label.config(text=f"Strength: {strength_text[score]} ({score}/4)")
        self.crack_time_label.config(text=f"Crack time: {result['crack_time']}")
        self.suggestions_label.config(text=f"Suggestions: {', '.join(result['suggestions']) or 'None'}")

        # Breach Check in background thread
        def run_pwned_check():
            pwned_result = check_pwned_password(password)
            self.pwned_label.config(text=pwned_result)

        threading.Thread(target=run_pwned_check, daemon=True).start()

    def run(self):
        """Run main event loop."""
        self.root.mainloop()
