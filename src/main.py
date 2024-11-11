import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets
import string

# Password Generator Logic
def generate_password(length=12):
    """Generates a random password with letters, digits, and special characters."""
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(all_characters) for _ in range(length))
    return password

# Hashing Function (SHA-256)
def hash_password(password):
    """Hashes the password using SHA-256."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))
    return sha256_hash.hexdigest()

# Password Strength Indicator
def check_strength(password):
    """Check the strength of the password based on length and variety of characters."""
    length_score = len(password) >= 12
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    score = length_score + has_upper + has_lower + has_digit + has_special
    if score == 5:
        return "Strong"
    elif score == 4:
        return "Moderate"
    elif score >= 2:
        return "Weak"
    else:
        return "Very Weak"

# GUI Logic with Tkinter
class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Generator")
        self.root.geometry("400x350")  # Window size

        # Create widgets
        self.title_label = tk.Label(root, text="Secure Password Generator", font=("Arial", 14))
        self.title_label.pack(pady=10)

        self.password_label = tk.Label(root, text="Generated Password:", font=("Arial", 10))
        self.password_label.pack(pady=5)

        self.password_output = tk.Entry(root, font=("Arial", 12), width=30, state="readonly")
        self.password_output.pack(pady=5)

        self.hash_label = tk.Label(root, text="Hashed Password:", font=("Arial", 10))
        self.hash_label.pack(pady=5)

        self.hash_output = tk.Entry(root, font=("Arial", 12), width=30, state="readonly")
        self.hash_output.pack(pady=5)

        self.strength_label = tk.Label(root, text="Password Strength: Not Generated", font=("Arial", 10))
        self.strength_label.pack(pady=5)

        self.generate_button = tk.Button(root, text="Generate Password", font=("Arial", 12), command=self.generate_and_display)
        self.generate_button.pack(pady=10)

        self.copy_button = tk.Button(root, text="Copy to Clipboard", font=("Arial", 12), command=self.copy_password)
        self.copy_button.pack(pady=5)

    def generate_and_display(self):
        """Generate password, hash it, and check strength."""
        password = generate_password(12)  # Length can be adjusted
        hashed_password = hash_password(password)
        strength = check_strength(password)

        # Update the UI with the generated data
        self.password_output.config(state="normal")
        self.password_output.delete(0, tk.END)
        self.password_output.insert(0, password)
        self.password_output.config(state="readonly")

        self.hash_output.config(state="normal")
        self.hash_output.delete(0, tk.END)
        self.hash_output.insert(0, hashed_password)
        self.hash_output.config(state="readonly")

        self.strength_label.config(text=f"Password Strength: {strength}")

    def copy_password(self):
        """Copy the generated password to clipboard."""
        password = self.password_output.get()
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
