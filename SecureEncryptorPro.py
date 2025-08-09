"""
SecureEncryptorPro - AES + RSA Hybrid File Encryption (single-file GUI)

Requirements:
    pip install pycryptodome tkinterdnd2 pillow

Notes:
 - Change MASTER_PASSWORD below before sharing or production use.
 - RSA private keys are saved in PEM format (no passphrase). Consider adding passphrase protection.
 - Encryption file format produced: [enc_session_key][nonce(16)][tag(16)][ciphertext]
   where enc_session_key length depends on RSA key size (e.g. 256 bytes for 2048-bit RSA).
"""

import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Drag-and-drop support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:
    # If tkinterdnd2 isn't installed, we'll gracefully fall back to file dialogs.
    TkinterDnD = tk.Tk
    DND_FILES = None

# Small tooltip helper
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, _event=None):
        if self.tipwindow or not self.text:
            return
        try:
            x, y, cx, cy = self.widget.bbox("insert")
            x += self.widget.winfo_rootx() + 25
            y += self.widget.winfo_rooty() + 20
        except Exception:
            x = self.widget.winfo_rootx() + 25
            y = self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#333333", foreground="#ffffff",
                         relief=tk.SOLID, borderwidth=1,
                         font=("Segoe UI", 9))
        label.pack(ipadx=5, ipady=2)

    def hide_tip(self, _event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

# Change this before publishing
MASTER_PASSWORD = "securepass"

class SecureEncryptorPro:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureEncryptorPro - AES + RSA Hybrid Encryption")
        self.root.geometry("880x620")
        self.root.configure(bg="#1e1e1e")
        self.root.resizable(False, False)

        # Crypto keys
        self.rsa_key_pair = None
        self.public_key = None
        self.private_key = None

        # GUI state variables
        self.enc_file_path = tk.StringVar()
        self.dec_file_path = tk.StringVar()

        # Ask for master password
        if not self._require_password():
            self.root.destroy()
            return

        # Setup UI
        self._setup_styles()
        self._create_tabs()
        self.append_status("Application started.")

    # ---------------------------
    # Authentication
    # ---------------------------
    def _require_password(self):
        pw = simpledialog.askstring("Authentication", "Enter master password:", show="*")
        if pw is None:
            return False
        if pw != MASTER_PASSWORD:
            messagebox.showerror("Access Denied", "Incorrect password.")
            return False
        return True

    # ---------------------------
    # UI: styles and tabs
    # ---------------------------
    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", background="#2a2a2a", borderwidth=0)
        style.configure("TNotebook.Tab", background="#303030", foreground="#ffffff", padding=[12, 6], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", "#4b3bff")])
        style.configure("TButton", background="#4b3bff", foreground="#ffffff", font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#5f47ff")])
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        style.configure("TFrame", background="#1e1e1e")

    def _create_tabs(self):
        self.tabControl = ttk.Notebook(self.root)

        self.tab_encrypt = ttk.Frame(self.tabControl)
        self.tab_decrypt = ttk.Frame(self.tabControl)
        self.tab_keys = ttk.Frame(self.tabControl)
        self.tab_settings = ttk.Frame(self.tabControl)

        self.tabControl.add(self.tab_encrypt, text="Encrypt")
        self.tabControl.add(self.tab_decrypt, text="Decrypt")
        self.tabControl.add(self.tab_keys, text="Key Management")
        self.tabControl.add(self.tab_settings, text="Settings")

        self.tabControl.pack(expand=1, fill="both", padx=8, pady=8)

        self._create_encrypt_tab()
        self._create_decrypt_tab()
        self._create_key_tab()
        self._create_settings_tab()

    # ---------------------------
    # Encrypt tab
    # ---------------------------
    def _create_encrypt_tab(self):
        ttk.Label(self.tab_encrypt, text="Select a file to encrypt:").pack(anchor="w", pady=(12, 6), padx=12)
        entry_frame = tk.Frame(self.tab_encrypt, bg="#1e1e1e")
        entry_frame.pack(fill="x", padx=12)

        self.enc_entry = ttk.Entry(entry_frame, textvariable=self.enc_file_path, width=80)
        self.enc_entry.pack(side="left", padx=(0,8), pady=6)
        # Drag-and-drop if available
        if DND_FILES:
            try:
                self.enc_entry.drop_target_register(DND_FILES)
                self.enc_entry.dnd_bind('<<Drop>>', lambda e: self._handle_drag(e, self.enc_file_path))
            except Exception:
                pass

        btn_browse = ttk.Button(entry_frame, text="Browse", command=self.browse_file_to_encrypt)
        btn_browse.pack(side="left")
        Tooltip(btn_browse, "Browse for file to encrypt")

        # Mode selection
        mode_frame = tk.Frame(self.tab_encrypt, bg="#1e1e1e")
        mode_frame.pack(anchor="w", padx=12, pady=(6,0))
        self.mode_var = tk.StringVar(value="hybrid")
        tk.Radiobutton(mode_frame, text="AES + RSA (Hybrid)", variable=self.mode_var, value="hybrid",
                       bg="#1e1e1e", fg="#ffffff", selectcolor="#1e1e1e", activebackground="#1e1e1e").pack(side="left", padx=(0,10))
        tk.Radiobutton(mode_frame, text="RSA Only", variable=self.mode_var, value="rsa_only",
                       bg="#1e1e1e", fg="#ffffff", selectcolor="#1e1e1e", activebackground="#1e1e1e").pack(side="left")

        btn_encrypt = ttk.Button(self.tab_encrypt, text="Encrypt File", command=self.encrypt_file)
        btn_encrypt.pack(pady=12)
        Tooltip(btn_encrypt, "Encrypt the selected file (hybrid mode recommended)")

        ttk.Separator(self.tab_encrypt, orient="horizontal").pack(fill="x", padx=12, pady=8)

    # ---------------------------
    # Decrypt tab
    # ---------------------------
    def _create_decrypt_tab(self):
        ttk.Label(self.tab_decrypt, text="Select a file to decrypt:").pack(anchor="w", pady=(12,6), padx=12)
        entry_frame = tk.Frame(self.tab_decrypt, bg="#1e1e1e")
        entry_frame.pack(fill="x", padx=12)

        self.dec_entry = ttk.Entry(entry_frame, textvariable=self.dec_file_path, width=80)
        self.dec_entry.pack(side="left", padx=(0,8), pady=6)
        if DND_FILES:
            try:
                self.dec_entry.drop_target_register(DND_FILES)
                self.dec_entry.dnd_bind('<<Drop>>', lambda e: self._handle_drag(e, self.dec_file_path))
            except Exception:
                pass

        btn_browse = ttk.Button(entry_frame, text="Browse", command=self.browse_file_to_decrypt)
        btn_browse.pack(side="left")
        Tooltip(btn_browse, "Browse for file to decrypt")

        btn_decrypt = ttk.Button(self.tab_decrypt, text="Decrypt File", command=self.decrypt_file)
        btn_decrypt.pack(pady=12)
        Tooltip(btn_decrypt, "Decrypt the selected .enc file")

        ttk.Separator(self.tab_decrypt, orient="horizontal").pack(fill="x", padx=12, pady=8)

    # ---------------------------
    # Key Management tab
    # ---------------------------
    def _create_key_tab(self):
        frame = tk.Frame(self.tab_keys, bg="#1e1e1e")
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Button(frame, text="Generate RSA Key Pair (2048)", command=self.generate_keys).pack(pady=6)
        ttk.Button(frame, text="Save Public Key", command=self.save_public_key).pack(pady=6)
        ttk.Button(frame, text="Save Private Key", command=self.save_private_key).pack(pady=6)
        ttk.Button(frame, text="Load Public Key", command=self.load_public_key).pack(pady=6)
        ttk.Button(frame, text="Load Private Key", command=self.load_private_key).pack(pady=6)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(frame, text="Status / Logs:").pack(anchor="w", pady=(6,2))
        self.status_display = scrolledtext.ScrolledText(frame, height=8, wrap=tk.WORD,
                                                        font=("Consolas", 10), bg="#252526", fg="#ffffff")
        self.status_display.pack(fill="both", expand=True, pady=(0,6))
        self.append_status("Ready for key operations.")

    # ---------------------------
    # Settings tab (placeholder)
    # ---------------------------
    def _create_settings_tab(self):
        frame = tk.Frame(self.tab_settings, bg="#1e1e1e")
        frame.pack(fill="both", expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Settings & Advanced Options (placeholder)").pack(anchor="w")
        ttk.Label(frame, text="You can add options here: password-protect keys, key directory, etc.").pack(anchor="w", pady=(6,0))

    # ---------------------------
    # Utility UI helpers
    # ---------------------------
    def append_status(self, message: str):
        try:
            self.status_display.insert(tk.END, message + "\n")
            self.status_display.see(tk.END)
        except Exception:
            # if status widget not present yet, print to console
            print(message)

    def _handle_drag(self, event, var: tk.StringVar):
        # event.data can contain braces around path on Windows
        path = event.data
        if isinstance(path, str):
            path = path.strip()
            # sometimes paths are like "{C:\path\file.txt}" with braces
            if path.startswith("{") and path.endswith("}"):
                path = path[1:-1]
            # only keep first path if multiple dragged
            if " " in path and os.path.exists(path.split(" ")[0]):
                path = path.split(" ")[0]
            var.set(path)
            self.append_status(f"File dropped: {path}")

    # ---------------------------
    # File dialogs
    # ---------------------------
    def browse_file_to_encrypt(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self.enc_file_path.set(path)
            self.append_status(f"Selected for encryption: {path}")

    def browse_file_to_decrypt(self):
        path = filedialog.askopenfilename(title="Select file to decrypt")
        if path:
            self.dec_file_path.set(path)
            self.append_status(f"Selected for decryption: {path}")

    # ---------------------------
    # Key operations
    # ---------------------------
    def generate_keys(self):
        try:
            self.rsa_key_pair = RSA.generate(2048)
            self.public_key = self.rsa_key_pair.publickey()
            self.private_key = self.rsa_key_pair
            self.append_status("RSA key pair generated (2048 bits).")
            messagebox.showinfo("Keys", "RSA key pair generated in memory.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
            self.append_status(f"Key generation error: {str(e)}")

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning("No Key", "No public key present. Generate or load one first.")
            return
        path = filedialog.asksaveasfilename(title="Save Public Key", defaultextension=".pem", filetypes=[("PEM files","*.pem")])
        if path:
            with open(path, "wb") as f:
                f.write(self.public_key.export_key(format='PEM'))
            self.append_status(f"Public key saved: {path}")
            messagebox.showinfo("Saved", "Public key saved.")

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning("No Key", "No private key present. Generate or load one first.")
            return
        path = filedialog.asksaveasfilename(title="Save Private Key", defaultextension=".pem", filetypes=[("PEM files","*.pem")])
        if path:
            with open(path, "wb") as f:
                f.write(self.private_key.export_key(format='PEM'))
            self.append_status(f"Private key saved: {path}")
            messagebox.showinfo("Saved", "Private key saved.")

    def load_public_key(self):
        path = filedialog.askopenfilename(title="Load Public Key", filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "rb") as f:
                    self.public_key = RSA.import_key(f.read())
                self.append_status(f"Public key loaded: {path}")
                messagebox.showinfo("Loaded", "Public key loaded.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {str(e)}")
                self.append_status(f"Public key load error: {str(e)}")

    def load_private_key(self):
        path = filedialog.askopenfilename(title="Load Private Key", filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "rb") as f:
                    self.private_key = RSA.import_key(f.read())
                self.append_status(f"Private key loaded: {path}")
                messagebox.showinfo("Loaded", "Private key loaded.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {str(e)}")
                self.append_status(f"Private key load error: {str(e)}")

    # ---------------------------
    # Encryption / Decryption
    # ---------------------------
    def encrypt_file(self):
        file_path = self.enc_file_path.get().strip()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showwarning("No File", "Please select a valid file to encrypt.")
            return

        if self.mode_var.get() == "rsa_only":
            # RSA-only mode: encrypt file in chunks <= RSA key size - padding
            if not self.public_key:
                messagebox.showwarning("No Public Key", "Load or generate a public key first.")
                return
            try:
                data = open(file_path, "rb").read()
                cipher_rsa = PKCS1_OAEP.new(self.public_key)
                # RSA only approach: not recommended for large files (will fail if too big)
                enc = cipher_rsa.encrypt(data)
                out_file = file_path + ".rsa.enc"
                with open(out_file, "wb") as f:
                    f.write(enc)
                self.append_status(f"RSA-only encrypted saved to: {out_file}")
                messagebox.showinfo("Encrypted", f"RSA-only encryption saved: {out_file}")
            except ValueError as e:
                messagebox.showerror("Error", "File too large for RSA-only encryption. Use hybrid AES+RSA mode.")
                self.append_status(f"RSA-only encryption failed: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
                self.append_status(f"Encryption error: {str(e)}")
            return

        # Hybrid AES+RSA mode (recommended)
        if not self.public_key:
            messagebox.showwarning("No Public Key", "Load or generate a public key first.")
            return

        try:
            data = open(file_path, "rb").read()
            session_key = get_random_bytes(16)  # AES-128 session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)

            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            out_file = file_path + ".enc"
            with open(out_file, "wb") as f:
                # Write enc_session_key length is implicit (fixed by RSA key size)
                f.write(enc_session_key)
                f.write(cipher_aes.nonce)  # 16 bytes
                f.write(tag)              # 16 bytes
                f.write(ciphertext)

            self.append_status(f"File encrypted and saved to: {out_file}")
            messagebox.showinfo("Encrypted", f"File encrypted and saved to: {out_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.append_status(f"Encryption error: {str(e)}")

    def decrypt_file(self):
        file_path = self.dec_file_path.get().strip()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showwarning("No File", "Please select a valid encrypted file to decrypt.")
            return

        if self.mode_var.get() == "rsa_only":
            if not self.private_key:
                messagebox.showwarning("No Private Key", "Load or generate a private key first.")
                return
            # Decrypt RSA-only file
            try:
                enc = open(file_path, "rb").read()
                cipher_rsa = PKCS1_OAEP.new(self.private_key)
                dec = cipher_rsa.decrypt(enc)
                out_file = file_path + ".dec"
                with open(out_file, "wb") as f:
                    f.write(dec)
                self.append_status(f"RSA-only decrypted saved to: {out_file}")
                messagebox.showinfo("Decrypted", f"RSA-only decryption saved: {out_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
                self.append_status(f"Decryption error: {str(e)}")
            return

        # Hybrid AES+RSA decryption
        try:
            with open(file_path, "rb") as f:
                # compute RSA key size in bytes (we expect enc_session_key to be this length)
                if not self.private_key:
                    messagebox.showwarning("No Private Key", "Load or generate a private key first.")
                    return
                rsa_key_size = self.private_key.size_in_bits() // 8
                enc_session_key = f.read(rsa_key_size)
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()

            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            out_file = file_path
            if out_file.endswith(".enc"):
                out_file = out_file[:-4] + ".dec"
            else:
                out_file = file_path + ".dec"

            with open(out_file, "wb") as f:
                f.write(data)

            self.append_status(f"File decrypted and saved to: {out_file}")
            messagebox.showinfo("Decrypted", f"File decrypted and saved to: {out_file}")
        except ValueError as e:
            messagebox.showerror("Integrity Error", f"Decryption failed - authentication error: {str(e)}")
            self.append_status(f"Decryption auth error: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.append_status(f"Decryption error: {str(e)}")

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    # Use TkinterDnD if available for drag and drop; fallback to normal Tk otherwise
    try:
        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    app = SecureEncryptorPro(root)
    root.mainloop()
