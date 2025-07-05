import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# --- AES Encryption Logic ---

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(message.encode()) % 16)
    padded_message = message + chr(padding_length) * padding_length
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(salt + iv + ciphertext).decode()

def decrypt_message(encrypted: str, password: str) -> str:
    data = base64.urlsafe_b64decode(encrypted)
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    return padded_plaintext[:-padding_length].decode()

# --- GUI Theme Switch Logic ---

def apply_theme(mode):
    if mode == "Light":
        colors = {
            "bg": "#f0f0f0",
            "fg": "#000000",
            "entry_bg": "#ffffff",
            "text_bg": "#ffffff",
            "text_fg": "#000000"
        }
    else:  # Dark
        colors = {
            "bg": "#2e2e2e",
            "fg": "#ffffff",
            "entry_bg": "#444444",
            "text_bg": "#333333",
            "text_fg": "#ffffff"
        }

    root.config(bg=colors["bg"])
    main_frame.config(style=f"{mode}.TFrame")
    message_entry.config(bg=colors["text_bg"], fg=colors["text_fg"], insertbackground=colors["fg"])
    output_text.config(bg=colors["text_bg"], fg=colors["text_fg"], insertbackground=colors["fg"])
    key_entry.config(background=colors["entry_bg"], foreground=colors["fg"], insertbackground=colors["fg"])
    
    for child in main_frame.winfo_children():
        if isinstance(child, ttk.Label):
            child.config(style=f"{mode}.TLabel")
        elif isinstance(child, ttk.Button):
            child.config(style=f"{mode}.TButton")
        elif isinstance(child, ttk.Combobox):
            child.config(style=f"{mode}.TCombobox")

# --- Action Functions ---

def encode_action():
    msg = message_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    if not msg or not key:
        messagebox.showerror("Input Error", "Message and key cannot be empty.")
        return
    try:
        encrypted = encrypt_message(msg, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decode_action():
    msg = message_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    if not msg or not key:
        messagebox.showerror("Input Error", "Encrypted message and key cannot be empty.")
        return
    try:
        decrypted = decrypt_message(msg, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def paste_input():
    try:
        clipboard = root.clipboard_get()
        message_entry.delete("1.0", tk.END)
        message_entry.insert(tk.END, clipboard)
    except tk.TclError:
        messagebox.showerror("Clipboard Error", "No text found in clipboard.")

def copy_output():
    output = output_text.get("1.0", tk.END).strip()
    if output:
        root.clipboard_clear()
        root.clipboard_append(output)
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    else:
        messagebox.showwarning("Empty Output", "Nothing to copy.")

def toggle_key_visibility():
    if key_entry.cget("show") == "":
        key_entry.config(show="*")
        toggle_key_btn.config(text="Show Key")
    else:
        key_entry.config(show="")
        toggle_key_btn.config(text="Hide Key")

def switch_theme(event=None):
    apply_theme(theme_var.get())

# --- GUI Setup ---

root = tk.Tk()
root.title("Secure Message Encoder/Decoder")
root.geometry("620x530")
root.resizable(False, False)

style = ttk.Style(root)

# Custom styles for light/dark
style.configure("Light.TFrame", background="#f0f0f0")
style.configure("Dark.TFrame", background="#2e2e2e")

style.configure("Light.TLabel", background="#f0f0f0", foreground="#000000")
style.configure("Dark.TLabel", background="#2e2e2e", foreground="#ffffff")

style.configure("Light.TButton", background="#ffffff")
style.configure("Dark.TButton", background="#444444", foreground="#ffffff")

style.configure("Light.TCombobox", fieldbackground="#ffffff", background="#ffffff", foreground="#000000")
style.configure("Dark.TCombobox", fieldbackground="#444444", background="#444444", foreground="#ffffff")

main_frame = ttk.Frame(root, padding=15)
main_frame.pack(fill=tk.BOTH, expand=True)

# Message Input
ttk.Label(main_frame, text="Message / Encrypted Text:").grid(row=0, column=0, sticky="w")
message_entry = tk.Text(main_frame, height=6, width=70, wrap="word", font=("Consolas", 10))
message_entry.grid(row=1, column=0, columnspan=3, pady=5)

ttk.Button(main_frame, text="Paste", command=paste_input).grid(row=1, column=3, padx=5, sticky="ns")

# Key Input
ttk.Label(main_frame, text="Secret Key:").grid(row=2, column=0, sticky="w", pady=(10, 0))
key_entry = tk.Entry(main_frame, show="*", width=40)
key_entry.grid(row=3, column=0, sticky="w")

toggle_key_btn = ttk.Button(main_frame, text="Show Key", command=toggle_key_visibility)
toggle_key_btn.grid(row=3, column=1, sticky="w", padx=(10, 0))

# Buttons
btn_frame = ttk.Frame(main_frame)
btn_frame.grid(row=4, column=0, columnspan=4, pady=15)

ttk.Button(btn_frame, text="Encrypt", width=20, command=encode_action).pack(side=tk.LEFT, padx=10)
ttk.Button(btn_frame, text="Decrypt", width=20, command=decode_action).pack(side=tk.LEFT, padx=10)

# Output
ttk.Label(main_frame, text="Output:").grid(row=5, column=0, sticky="w")
output_text = tk.Text(main_frame, height=6, width=70, wrap="word", font=("Consolas", 10))
output_text.grid(row=6, column=0, columnspan=3, pady=5)

ttk.Button(main_frame, text="Copy Output", command=copy_output).grid(row=6, column=3, padx=5, sticky="ns")

# Theme Selection
ttk.Label(main_frame, text="Theme:").grid(row=7, column=0, sticky="w", pady=(15, 0))
theme_var = tk.StringVar(value="Light")
theme_combo = ttk.Combobox(main_frame, values=["Light", "Dark"], textvariable=theme_var, state="readonly", width=20)
theme_combo.grid(row=7, column=1, sticky="w", pady=(15, 0))
theme_combo.bind("<<ComboboxSelected>>", switch_theme)

# Apply default theme
apply_theme("Light")

root.mainloop()
