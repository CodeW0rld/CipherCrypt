import tkinter as tk
from tkinter import messagebox
import os

# Class for encrypting and decrypting messages
class CaesarCipher:
    def __init__(self, key):
        self.key = key  # Store the encryption/decryption key

    # Encrypt the message
    def encrypt(self, plaintext):
        result = ""
        for char in plaintext:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - base + self.key) % 26 + base)
            else:
                result += char
        return result

    # Decrypt the message
    def decrypt(self, ciphertext):
        result = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - base - self.key) % 26 + base)
            else:
                result += char
        return result

# Class for saving and loading encrypted messages
class FileManager:
    # Save the encrypted message and key to a file
    def save_message(self, user_name, message, key):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, f"{user_name}_message.txt")

        with open(file_path, 'w') as file:
            file.write(message)
            file.write(f"\nKey: {key}")

    # Load the encrypted message and key from a file
    def load_message(self, user_name):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, f"{user_name}_message.txt")

        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                if not lines:  # Check if the file is empty
                    messagebox.showerror("Error", f"The file for {user_name} is empty.")
                    return None, None
                ciphertext = lines[0].strip()
                try:
                    key = int(lines[1].split(": ")[1])
                except (IndexError, ValueError):  # Handle corrupted key line
                    messagebox.showerror("Error", f"The key in the file for {user_name} is corrupted.")
                    return None, None
                return ciphertext, key
        except FileNotFoundError:
            messagebox.showerror("Error", f"No encrypted message found for {user_name}.")
            return None, None

class CipherCryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherCrypt")
        self.root.configure(bg="tan1")
        self.root.geometry("350x450")

        # Create a title label
        title_label = tk.Label(self.root, text="CipherCrypt", font=("Arial", 24, "bold"), bg="tan1", fg="White")
        title_label.pack(pady=20)

        self.file_manager = FileManager()
        self.cipher = None
        self.attempts = 0

        self.create_main_window()

    # Create the main window
    def create_main_window(self):
        button_frame = tk.Frame(bg="tan1")
        button_frame.pack(pady=50)

        self.encryption_button = tk.Button(button_frame, text="Encrypt", command=self.show_encryption_window, bg='springgreen3', font=("Arial", 14), width=10, height=2)
        self.decryption_button = tk.Button(button_frame, text="Decrypt", command=self.show_decryption_window, bg='salmon', font=("Arial", 14), width=10, height=2)
        self.exit_button = tk.Button(button_frame, text="Exit", command=self.root.destroy, bg='red3', font=("Arial", 14), width=10, height=2)

        self.encryption_button.grid(row=0, column=0, padx=10, pady=10)
        self.decryption_button.grid(row=1, column=0, padx=10, pady=10)
        self.exit_button.grid(row=2, column=0, padx=10, pady=10)

    # Create the encryption window
    def show_encryption_window(self):
        encryption_window = tk.Toplevel(self.root)
        encryption_window.title("Encryption")
        encryption_window.configure(bg="lightgray")  # Set the background color of the encryption window

        user_name_label = tk.Label(encryption_window, text="Type your User ID")
        self.user_name_var = tk.StringVar()
        user_name_entry = tk.Entry(encryption_window, textvariable=self.user_name_var)
        key_label = tk.Label(encryption_window, text="Type the key (1-26)")
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(encryption_window, textvariable=self.key_var)
        message_label = tk.Label(encryption_window, text="Type your message")
        self.message_var = tk.Text(encryption_window, height=5, width=39)
        encrypt_button = tk.Button(encryption_window, text="Encrypt", command=self.encrypt_message, bg='springgreen3')

        user_name_label.grid(row=0, column=0, padx=10, pady=5)
        user_name_entry.grid(row=0, column=1, padx=10, pady=5)
        key_label.grid(row=1, column=0, padx=10, pady=5)
        key_entry.grid(row=1, column=1, padx=10, pady=5)
        message_label.grid(row=2, column=0, padx=10, pady=5)
        self.message_var.grid(row=2, column=1, padx=10, pady=5)
        encrypt_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    # Encrypt the message and save it to a file
    def encrypt_message(self):
        user_name = self.user_name_var.get()
        key_str = self.key_var.get()

    # Check if the user ID already exists
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, f"{user_name}_message.txt")
        if os.path.isfile(file_path):
            messagebox.showerror("Error", f"The user ID '{user_name}' already exists. Please try again with a different user ID.")
            return

        if not key_str or not key_str.isdigit() or int(key_str) < 1 or int(key_str) > 26:
            messagebox.showerror("Error", "Key must be an integer between 1 and 26.")
            return

        key = int(key_str)
        message = self.message_var.get("1.0", tk.END).strip()
        self.cipher = CaesarCipher(key)
        ciphertext = self.cipher.encrypt(message)
        self.file_manager.save_message(user_name, ciphertext, key)

        message_box = messagebox.askquestion("Encryption Complete",
                                          "The encrypted message has been saved to the file. Do you wish to continue to decryption?")
        if message_box == 'yes':
            self.show_decryption_window()
        else:
            self.root.destroy()

    # Create the decryption window
    def show_decryption_window(self):
        decryption_window = tk.Toplevel(self.root)
        decryption_window.title("Decryption")
        decryption_window.configure(bg="lightgray")  # Set the background color of the decryption window

        user_name_label = tk.Label(decryption_window, text="Type your user ID")
        self.user_name_var = tk.StringVar()
        user_name_entry = tk.Entry(decryption_window, textvariable=self.user_name_var)
        key_label = tk.Label(decryption_window, text="Type the key (1-26)")
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(decryption_window, textvariable=self.key_var)
        message_label = tk.Label(decryption_window, text="Decrypted message")
        self.message_var = tk.Text(decryption_window, height=5, width=39)
        decrypt_button = tk.Button(decryption_window, text="Decrypt", command=self.decrypt_message, bg='salmon')

        user_name_label.grid(row=0, column=0, padx=10, pady=5)
        user_name_entry.grid(row=0, column=1, padx=10, pady=5)
        key_label.grid(row=1, column=0, padx=10, pady=5)
        key_entry.grid(row=1, column=1, padx=10, pady=5)
        message_label.grid(row=2, column=0, padx=10, pady=5)
        self.message_var.grid(row=2, column=1, padx=10, pady=5)
        decrypt_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    # Decrypt the message and display the result
    def decrypt_message(self):
        user_name = self.user_name_var.get()
        key_str = self.key_var.get()

        if not key_str or not key_str.isdigit() or int(key_str) < 1 or int(key_str) > 26:
            messagebox.showerror("Error", "Key must be an integer between 1 and 26.")
            return

        key = int(key_str)
        ciphertext, stored_key = self.file_manager.load_message(user_name)

        if key == stored_key:
                messagebox.showinfo("Congrats! :)", "The encrypted message has been successfully decrypted!")

        elif ciphertext is None or stored_key is None:
            return

        if key != stored_key:
            self.attempts += 1
            remaining_attempts = 3 - self.attempts
            if remaining_attempts > 0:
                messagebox.showerror("Error_666", f"Wrong key. You have {remaining_attempts} attempt(s) remaining.")
            else:
                messagebox.showerror("Error_666", "WRONG KEY! That was your last change. Closing the program :c")
                self.root.destroy()
            return

        self.cipher = CaesarCipher(key)
        plaintext = self.cipher.decrypt(ciphertext)

        self.message_var.delete("1.0", tk.END)
        self.message_var.insert(tk.END, plaintext)

if __name__ == "__main__":
    root = tk.Tk()
    gui = CipherCryptGUI(root)
    root.mainloop()