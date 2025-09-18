
import argparse
import os
import sys
import json
import getpass
import base64
from cryptography.fernet import Fernet, InvalidToken

vault_file = "passwords.vault"
max_input = 15
min_master_pass = 6

 
def generate_key_from_pass(password: str, salt: bytes = None) -> tuple:
   
   # make encryption key from pass. it will return (key, salt) tuple.
  
    if salt is None:
        salt = os.urandom(16)
    key = base64.urlsafe_b64encode(
        (password + salt.hex())[:32].encode().ljust(32, b'0')
    )
    return key, salt

def encrypt_data(data: str, key: bytes) -> bytes:
    #encrypt string data with fernet
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    #decrypt string encryption with fernet
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

def save_vault_dict(vault_dict: dict, key: bytes, salt: bytes):

    plaintext = json.dumps(vault_dict, ensure_ascii=False)
    token = encrypt_data(plaintext, key)  # bytes
    on_disk = {
        "salt": salt.hex(),
        "vault": token.decode()
    }
    with open(vault_file, "w", encoding="utf-8") as f:
        json.dump(on_disk, f)

def load_vault_dict(master_password: str):
    
    #This will load and decrypt vault file with master pass. 
    
    if not os.path.exists(vault_file):
        raise FileNotFoundError

    with open(vault_file, "r", encoding="utf-8") as f:
        on_disk = json.load(f)

    if "salt" not in on_disk or "vault" not in on_disk:
        raise InvalidToken  # malformed/corrupted file

    salt = bytes.fromhex(on_disk["salt"])
    token_str = on_disk["vault"]
    key, _ = generate_key_from_pass(master_password, salt=salt)

    plaintext = decrypt_data(token_str.encode(), key)
    vault_dict = json.loads(plaintext)
    return vault_dict, key, salt

# ---- Input validation ----
def validate_input(name: str, value: str):
    if not value:
        print(f"Invalid {name}: value is empty.")
        return False
    if len(value) > max_input:
        print(f"Invalid {name}: length must be <= {max_input} characters.")
        return False
    return True

def init_vault():
    #makes new vault with master pass
    if os.path.exists(vault_file):
        confirm = input(f"A vault already exists at '{vault_file}'. Overwrite? (y/n): ").strip().lower()
        if confirm != "y":
            print("Vault initialization cancelled.")
            return

    while True:
        master = getpass.getpass("Enter master password: ")
        if len(master) < min_master_pass:
            print(f"Master password must be at least {min_master_pass} characters.")
            continue
        confirm_pw = getpass.getpass("Confirm master password: ")
        if master != confirm_pw:
            print("Passwords do not match. Try again.")
            continue
        break

    key, salt = generate_key_from_pass(master)
    vault_dict = {}  # empty vault
    save_vault_dict(vault_dict, key, salt)
    print("✅ Vault created successfully!")

def add_password(website: str, username: str, password: str):
    if not (validate_input("website", website) and validate_input("username", username) and validate_input("password", password)):
        return

    try:
        master = getpass.getpass("Enter master password: ")
        vault_dict, key, salt = load_vault_dict(master)
    except FileNotFoundError:
        print("No vault found. Use 'init' to create one")
        return
    except InvalidToken:
        print("Invalid master pass")
        return

    vault_dict[website] = {"username": username, "password": password}
    save_vault_dict(vault_dict, key, salt)
    print(f"✅ Password added for {website}")

def get_password(website: str):
    if not validate_input("website", website):
        return

    try:
        master = getpass.getpass("Enter master pass: ")
        vault_dict, _, _ = load_vault_dict(master)
    except FileNotFoundError:
        print("No vault. Use 'init' to create one")
        return
    except InvalidToken:
        print("Invalid master pass")
        return

    entry = vault_dict.get(website)
    if not entry:
        print(f"No pass found for {website}")
        return

    print(f"🔑 {website} credentials:")
    print(f"   Username: {entry.get('username')}")
    print(f"   Password: {entry.get('password')}")

def list_websites():
    try:
        master = getpass.getpass("Enter master password: ")
        vault_dict, _, _ = load_vault_dict(master)
    except FileNotFoundError:
        print("No vault. Use 'init' to make one")
        return
    except InvalidToken:
        print("Invalid master pass")
        return

    if not vault_dict:
        print("No stored passwords.")
        return

    print("📋 Stored passwords:")
    for site, entry in vault_dict.items():
        print(f"   • {site} ({entry.get('username','')})")

#CLI 
def main():
    parser = argparse.ArgumentParser(description="Password Vault")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create new vault")

    add_parser = sub.add_parser("add", help="Add a password")
    add_parser.add_argument("website", help="website label (e.g., github.com)")
    add_parser.add_argument("username", help="username/email")
    add_parser.add_argument("password", help="password (use quotes if contains spaces)")

    get_parser = sub.add_parser("get", help="Get a password")
    get_parser.add_argument("website", help="website label (e.g., github.com)")

    sub.add_parser("list", help="List stored websites")

    args = parser.parse_args()

    if args.command == "init":
        init_vault()
    elif args.command == "add":
        add_password(args.website, args.username, args.password)
    elif args.command == "get":
        get_password(args.website)
    elif args.command == "list":
        list_websites()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
