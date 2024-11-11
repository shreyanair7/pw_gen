import tkinter as tk
from tkinter import messagebox
from password_generator import generate_password
from password_hasher import hash_password
from password_strength import check_strength


class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x500")

        # Create the UI components
        self.create_widgets()

    def create_widgets(self):
        # Title Label
        self.title_label = tk.Label(self.root, text="Password Generator", font=("Helvetica", 16))
        self.title_label.pack(pady=20)

        # Password length input
        self.length_label = tk.Label(self.root, text="Password Length:")
        self.length_label.pack()
        self.length_entry = tk.Entry(self.root)
        self.length_entry.insert(0, "12")  # Default length is 12
        self.length_entry.pack(pady=5)

        # Generate Password Button
        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password_action)
        self.generate_button.pack(pady=10)

        # Generated Password Display
        self.password_label = tk.Label(self.root, text="Generated Password:", font=("Helvetica", 10, "bold"))
        self.password_label.pack(pady=5)

        self.password_text = tk.Label(self.root, text="", font=("Helvetica", 10))
        self.password_text.pack()

        # Password Strength Label
        self.strength_label = tk.Label(self.root, text="Password Strength:", font=("Helvetica", 10, "bold"))
        self.strength_label.pack(pady=5)

        self.strength_text = tk.Label(self.root, text="", font=("Helvetica", 10))
        self.strength_text.pack()

        # Hash Password Button
        self.hash_button = tk.Button(self.root, text="Hash Password", command=self.hash_password_action)
        self.hash_button.pack(pady=10)

        # Hashed Password Display
        self.hashed_label = tk.Label(self.root, text="Hashed Password:", font=("Helvetica", 10, "bold"))
        self.hashed_label.pack(pady=5)

        self.hashed_text = tk.Label(self.root, text="", font=("Helvetica", 10))
        self.hashed_text.pack()

        # Copy to Clipboard Button
        self.copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=10)

        # Educational explanation about password hashing process using a scrollable Text widget
        self.hash_explanation_text = tk.Text(self.root, height=10, width=45, wrap="word", font=("Arial", 10), bg="lightgray")
        self.hash_explanation_text.insert(tk.END, """ 
            Explanation of Hashing and 
            Password Security:
            • Hashing is a one-way function that converts 
            a password into a fixed-length string, making 
            it nearly impossible to reverse.
            • Passwords should never be stored in plain 
            text; instead, only their hashed versions 
            should be saved in databases.
            • When a user logs in, their entered password
            is hashed and compared to the stored hash.
            • If the hashed password matches the stored 
            hash, the user is authenticated; if not, 
            access is denied.
            • This provides an example of how passwords 
            should not be stored in plain text, 
            highlighting the importance of hashing.
        """)
        self.hash_explanation_text.config(state=tk.DISABLED)  # Make the Text widget read-only
        self.hash_explanation_text.pack(padx=10, pady=10)


        # Educational explanation about password hashing process
        #self.hash_explanation_label = tk.Label(self.root, text=""" 
            #Explanation of Hashing and Password Security:
            #- Hashing is a one-way function that converts a password into a fixed-length string, making it nearly impossible to reverse.
            #- Passwords should never be stored in plain text; instead, only their hashed versions should be saved in databases.
            #- When a user logs in, their entered password is hashed and compared to the stored hash.
            #- If the hashed password matches the stored hash, the user is authenticated; if not, access is denied.
            #- This provides an example of how passwords should not be stored in plain text, highlighting the importance of hashing.
        
    #""", justify="left", wraplength=350, font=("Arial", 10), bg="lightgray")
        #self.hash_explanation_label.pack(padx=10, pady=10)

    def generate_password_action(self):
        try:
            # Get the length of the password from the input field
            length = int(self.length_entry.get())
            if length < 6:
                raise ValueError("Password length must be at least 6 characters.")
            
            # Generate the password
            password = generate_password(length)

            # Display the password
            self.password_text.config(text=password)

            # Check the password strength
            strength = check_strength(password)
            self.strength_text.config(text=strength)

        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))

    def hash_password_action(self):
        # Get the password displayed in the GUI
        password = self.password_text.cget("text")

        if not password:
            messagebox.showerror("Error", "Generate a password first.")
            return

        # Hash the password
        hashed_password = hash_password(password)

        # Display the hashed password
        self.hashed_text.config(text=hashed_password)

    def copy_to_clipboard(self):
        # Get the password or hashed password displayed
        text = self.password_text.cget("text") or self.hashed_text.cget("text")
        
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Text copied to clipboard")
        else:
            messagebox.showerror("Error", "No password to copy")


if __name__ == "__main__":
    # Create the main window
    root = tk.Tk()
    
    # Initialize the app
    app = PasswordApp(root)
    
    # Run the Tkinter main loop
    root.mainloop()
