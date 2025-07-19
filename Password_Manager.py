import customtkinter as ctk
from CTkMessagebox import CTkMessagebox as ctkmsg
from cryptography.fernet import Fernet
import os
import json

# File paths
KEY_FILE = "key.key"
MASTER_FILE = "master.pass"
VAULT_FILE = "vault.json"

# Key handling
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

fernet = Fernet(load_key())

# Master password functions
def set_master_password(master_pass):
    encrypted = fernet.encrypt(master_pass.encode())
    with open(MASTER_FILE, "wb") as f:
        f.write(encrypted)

def verify_master_password(input_pass):
    try:
        with open(MASTER_FILE, "rb") as f:
            encrypted = f.read()
        return fernet.decrypt(encrypted).decode() == input_pass
    except Exception:
        return False

# Vault handling
def save_vault(data):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    try:
        return json.loads(fernet.decrypt(encrypted).decode())
    except Exception:
        return {}

# GUI starts here
app = ctk.CTk()
app.title("Password Manager")
app.geometry("400x400")

vault_data = load_vault()

# UI callbacks
def handle_login():
    input_pass = pass_entry.get()
    if os.path.exists(MASTER_FILE):
        if verify_master_password(input_pass):
            show_vault_ui()
        else:
            ctkmsg(title="Error", message="Incorrect master password", icon="cancel")
    else:
        set_master_password(input_pass)
        ctkmsg(title="Success", message="Master password set", icon="check")
        show_vault_ui()

def add_entry():
    site = site_entry.get()
    user = user_entry.get()
    pwd = pwd_entry.get()
    if site and user and pwd:
        vault_data[site] = {"username": user, "password": pwd}
        save_vault(vault_data)
        refresh_vault_list()
        site_entry.delete(0, ctk.END)
        user_entry.delete(0, ctk.END)
        pwd_entry.delete(0, ctk.END)

# UI rendering
def show_vault_ui():
    for widget in app.winfo_children():
        widget.destroy()

    global site_entry, user_entry, pwd_entry

    ctk.CTkLabel(app, text="Site").pack()
    site_entry = ctk.CTkEntry(app)
    site_entry.pack()

    ctk.CTkLabel(app, text="Username").pack()
    user_entry = ctk.CTkEntry(app)
    user_entry.pack()

    ctk.CTkLabel(app, text="Password").pack()
    pwd_entry = ctk.CTkEntry(app)
    pwd_entry.pack()

    ctk.CTkButton(app, text="Add Entry", command=add_entry).pack(pady=10)
    global vault_listbox
    vault_listbox = ctk.CTkTextbox(app, height=150)
    vault_listbox.pack()
    refresh_vault_list()

def refresh_vault_list():
    vault_listbox.delete("1.0", ctk.END)
    for site, creds in vault_data.items():
        line = f"{site}: {creds['username']} / {creds['password']}\n"
        vault_listbox.insert(ctk.END, line)

# Login screen
ctk.CTkLabel(app, text="Enter Master Password").pack(pady=10)
pass_entry = ctk.CTkEntry(app, show="*")
pass_entry.pack(pady=5)
ctk.CTkButton(app, text="Login / Set", command=handle_login).pack(pady=10)

app.mainloop()
