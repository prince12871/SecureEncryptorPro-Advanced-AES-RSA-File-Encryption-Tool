import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

class SecureEncryptorPro:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureEncryptorPro - Advanced File Encryption")
        self.root.geometry("800x500")
        self.root.configure(bg="#121212")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#121212", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e1e1e", foreground="white", padding=10)
        style.map("TNotebook.Tab", background=[("selected", "#333333")])
        style.configure("TFrame", background="#121212")
        style.configure("TLabel", background="#121212", foreground="white")
        style.configure("TButton", background="#1e1e1e", foreground="white", padding=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.key_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.encrypt_tab, text="Encrypt")
        self.notebook.add(self.decrypt_tab, text="Decrypt")
        self.notebook.add(self.key_tab, text="Key Management")
        self.notebook.add(self.settings_tab, text="Settings")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_key_tab()

    def _build_encrypt_tab(self):
        ttk.Label(self.encrypt_tab, text="Select File to Encrypt:").pack(pady=10)
        self.encrypt_file_btn = ttk.Button(self.encrypt_tab, text="Browse File", command=self.encrypt_file)
        self.encrypt_file_btn.pack(pady=5)

    def _build_decrypt_tab(self):
        ttk.Label(self.decrypt_tab, text="Select File to Decrypt:").pack(pady=10)
        self.decrypt_file_btn = ttk.Button(self.decrypt_tab, text="Browse File", command=self.decrypt_file)
        self.decrypt_file_btn.pack(pady=5)

    def _build_key_tab(self):
        ttk.Label(self.key_tab, text="RSA Key Management").pack(pady=10)
        ttk.Button(self.key_tab, text="Generate RSA Key Pair", command=self.generate_rsa_keys).pack(pady=5)
        ttk.Button(self.key_tab, text="Load Public Key", command=self.load_public_key).pack(pady=5)
        ttk.Button(self.key_tab, text="Load Private Key", command=self.load_private_key).pack(pady=5)

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        messagebox.showinfo("Key Generation", "RSA Key Pair Generated Successfully!")

    def load_public_key(self):
        path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM Files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            messagebox.showinfo("Public Key", "Public Key Loaded Successfully!")

    def load_private_key(self):
        path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM Files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            messagebox.showinfo("Private Key", "Private Key Loaded Successfully!")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        with open(file_path, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        enc_aes_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        with open(file_path + ".enc", "wb") as f:
            f.write(iv + enc_aes_key + encrypted_data)
        messagebox.showinfo("Encryption", "File Encrypted Successfully!")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if not file_path:
            return
        with open(file_path, "rb") as f:
            iv = f.read(16)
            enc_aes_key = f.read(256)
            encrypted_data = f.read()
        aes_key = self.private_key.decrypt(
            enc_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        with open(file_path.replace(".enc", "_decrypted"), "wb") as f:
            f.write(decrypted_data)
        messagebox.showinfo("Decryption", "File Decrypted Successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEncryptorPro(root)
    root.mainloop()
