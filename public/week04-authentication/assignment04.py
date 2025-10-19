import bcrypt
import pyotp
import qrcode
import json
import os
import secrets
import re
from datetime import datetime
import argparse
import getpass

# pasword manager
class PasswordManager:
    def __init__(self):
        self.min_length = 8
        self.complexity_patterns = {
            'lowercase': r'[a-z]',
            'uppercase': r'[A-Z]',
            'digit': r'\d',
            'special': r'[!@#$%^&*(),.?":{}|<>]'
        }

    def check_password_strength(self, password):
        issues = []
        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")
        for rule_name, pattern in self.complexity_patterns.items():
            if not re.search(pattern, password):
                issues.append(f"Password must contain at least one {rule_name} character")
        return len(issues) == 0, issues

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def verify_password(self, password, stored_hash):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except Exception:
            return False

#store user
class SimpleUserStore:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = self.load_users()
        self.password_manager = PasswordManager()

    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                data = json.load(f)
                import base64
                for user in data.values():
                    if 'password_hash' in user:
                        user['password_hash'] = base64.b64decode(user['password_hash'])
                return data
        return {}

    def save_users(self):
        import base64
        data_to_save = {}
        for username, user_data in self.users.items():
            data_to_save[username] = user_data.copy()
            if 'password_hash' in data_to_save[username]:
                data_to_save[username]['password_hash'] = base64.b64encode(
                    data_to_save[username]['password_hash']
                ).decode('utf-8')
        with open(self.filename, 'w') as f:
            json.dump(data_to_save, f, indent=2)

    def create_user(self, username, password):
        if username in self.users:
            return False, "User already exists"
        is_strong, issues = self.password_manager.check_password_strength(password)
        if not is_strong:
            return False, issues
        password_hash = self.password_manager.hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat()
        }
        self.save_users()
        return True, "User created successfully"

    def authenticate_password(self, username, password):
        if username not in self.users:
            return False, "Invalid credentials"
        user = self.users[username]
        if self.password_manager.verify_password(password, user['password_hash']):
            return True, "Password verified"
        return False, "Invalid credentials"

# TOTP
class TOTPManager:
    def __init__(self):
        self.window_tolerance = 1

    def generate_secret(self):
        return pyotp.random_base32()

    def generate_qr_code(self, username, secret, issuer="MFA Demo"):
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        filename = f"{username}_qr.png"
        img.save(filename)
        return filename, secret

    def verify_totp(self, secret, token):
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=self.window_tolerance)

    def get_current_token(self, secret):
        totp = pyotp.TOTP(secret)
        return totp.now()

# -make backup codes
class BackupCodeManager:
    def __init__(self):
        self.code_length = 8
        self.num_codes = 10

    def generate_codes(self):
        return [secrets.token_hex(self.code_length // 2).upper() for _ in range(self.num_codes)]

    def hash_codes(self, codes):
        import hashlib
        return [hashlib.sha256(code.encode()).hexdigest() for code in codes]

    def verify_code(self, input_code, hashed_codes):
        import hashlib
        input_hash = hashlib.sha256(input_code.upper().encode()).hexdigest()
        return input_hash in hashed_codes

# MFA implementation
class SimpleMFA:
    def __init__(self):
        self.user_store = SimpleUserStore()
        self.totp_manager = TOTPManager()
        self.backup_manager = BackupCodeManager()

    def setup_user_mfa(self, username):
        if username not in self.user_store.users:
            return False, "User not found"
        secret = self.totp_manager.generate_secret()
        backup_codes = self.backup_manager.generate_codes()
        hashed_backup_codes = self.backup_manager.hash_codes(backup_codes)
        qr_filename, _ = self.totp_manager.generate_qr_code(username, secret)
        self.user_store.users[username].update({
            'totp_secret': secret,
            'backup_codes': hashed_backup_codes,
            'mfa_enabled': True
        })
        self.user_store.save_users()
        return True, {
            'qr_code': qr_filename,
            'secret': secret,
            'backup_codes': backup_codes
        }

    def authenticate_full(self, username, password, totp_token):
        password_ok, message = self.user_store.authenticate_password(username, password)
        if not password_ok:
            return False, message
        user = self.user_store.users[username]
        if not user.get('mfa_enabled'):
            return True, "Password-only authentication (MFA not set up)"
        if self.totp_manager.verify_totp(user['totp_secret'], totp_token):
            return True, "Full MFA authentication successful"
        if self.backup_manager.verify_code(totp_token, user['backup_codes']):
            import hashlib
            used_hash = hashlib.sha256(totp_token.upper().encode()).hexdigest()
            user['backup_codes'].remove(used_hash)
            self.user_store.save_users()
            remaining = len(user['backup_codes'])
            return True, f"Backup code accepted. {remaining} codes remaining."
        return False, "Invalid TOTP token or backup code"

# CLI commands
def test_password_component(mfa):
    print("🔒 Testing Password Component")
    weak_passwords = ["123", "password", "12345678"]
    strong_password = "StrongP@ssw0rd123"
    print("\nTesting password strength:")
    for pwd in weak_passwords:
        is_strong, issues = mfa.user_store.password_manager.check_password_strength(pwd)
        print(f"   '{pwd}': {'Strong' if is_strong else 'Weak'} - {issues}")
    is_strong, issues = mfa.user_store.password_manager.check_password_strength(strong_password)
    print(f"   '{strong_password}': {'Strong' if is_strong else 'Weak'}")
    print("\nTesting bcrypt hashing:")
    password_hash = mfa.user_store.password_manager.hash_password(strong_password)
    print(f"   Hash generated: {password_hash[:20]}...")
    verify_result = mfa.user_store.password_manager.verify_password(strong_password, password_hash)
    print(f"   Verification: {'Success' if verify_result else 'Failed'}")

def test_totp_component(mfa):
    print("📱 Testing TOTP Component")
    secret = mfa.totp_manager.generate_secret()
    current_token = mfa.totp_manager.get_current_token(secret)
    print(f"\nGenerated secret: {secret}")
    print(f"Current TOTP token: {current_token}")
    verify_result = mfa.totp_manager.verify_totp(secret, current_token)
    print(f"Token verification: {'Success' if verify_result else 'Failed'}")
    wrong_token = "000000"
    verify_wrong = mfa.totp_manager.verify_totp(secret, wrong_token)
    print(f"Wrong token verification: {'Rejected' if not verify_wrong else 'Incorrectly accepted'}")

def test_backup_component(mfa):
    print("Testing Backup Codes Component")
    codes = mfa.backup_manager.generate_codes()
    print(f"\nGenerated {len(codes)} backup codes:")
    for i, code in enumerate(codes[:3], 1):
        print(f"   {i}. {code}")
    print("   ...")
    hashed_codes = mfa.backup_manager.hash_codes(codes)
    test_code = codes[0]
    verify_result = mfa.backup_manager.verify_code(test_code, hashed_codes)
    print(f"Backup code verification: {'Success' if verify_result else 'Failed'}")
    wrong_code = "WRONGCODE"
    verify_wrong = mfa.backup_manager.verify_code(wrong_code, hashed_codes)
    print(f"Wrong backup code verification: {'Rejected' if not verify_wrong else 'Incorrectly accepted'}")

def main():
    parser = argparse.ArgumentParser(description="Simple MFA Analysis System")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    create_parser = subparsers.add_parser('create-user', help='Create new user')
    create_parser.add_argument('username', help='Username')
    setup_parser = subparsers.add_parser('setup-mfa', help='Setup MFA for user')
    setup_parser.add_argument('username', help='Username')
    auth_parser = subparsers.add_parser('authenticate', help='Test MFA authentication')
    auth_parser.add_argument('username', help='Username')
    test_parser = subparsers.add_parser('test', help='Test individual components')
    test_parser.add_argument('component', choices=['password', 'totp', 'backup'], help='Component to test')

    args = parser.parse_args()
    mfa = SimpleMFA()

    if args.command == 'create-user':
        password = getpass.getpass("Password: ")
        success, message = mfa.user_store.create_user(args.username, password)
        if success:
            print(f"User {args.username} created successfully!")
        else:
            print(f"Failed to create user: {message}")

    elif args.command == 'setup-mfa':
        success, result = mfa.setup_user_mfa(args.username)
        if success:
            print(f"MFA setup complete for {args.username}")
            print(f"QR code saved as: {result['qr_code']}")
            print(f"🔑 Manual setup key: {result['secret']}")
            print("\n Backup codes (save these securely!):")
            for i, code in enumerate(result['backup_codes'], 1):
                print(f"   {i:2d}. {code}")
        else:
            print(f"MFA setup failed: {result}")

    elif args.command == 'authenticate':
        password = getpass.getpass("Password: ")
        totp_token = input("Enter TOTP code or backup code: ")
        success, message = mfa.authenticate_full(args.username, password, totp_token)
        if success:
            print(f"{message}")
        else:
            print(f"Authentication failed: {message}")

    elif args.command == 'test':
        if args.component == 'password':
            test_password_component(mfa)
        elif args.component == 'totp':
            test_totp_component(mfa)
        elif args.component == 'backup':
            test_backup_component(mfa)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
