# Week 4 Homework Hints: Multi-Factor Authentication Analysis

## 🎯 Quick Start Guide (4 hours total)

### Time Breakdown
- **MFA Concepts & Research**: 1 hour
- **Password Authentication (bcrypt)**: 1 hour
- **TOTP Implementation (pyotp)**: 1 hour
- **Backup Codes & Analysis**: 1 hour

## 📋 Step-by-Step Implementation

### Step 1: Understanding MFA Components (30 minutes)

**Three Authentication Factors:**
1. **Something you know** (password) - Knowledge factor
2. **Something you have** (phone/token) - Possession factor
3. **Something you are** (biometrics) - Inherence factor

**Assignment Focus:**
- Implement simplified versions using existing libraries
- Analyze security properties of each factor
- Compare with real-world implementations

### Step 2: Environment Setup (15 minutes)

```bash
pip install bcrypt pyotp qrcode[pil]

mkdir week04-mfa-analysis
cd week04-mfa-analysis

touch mfa_system.py
touch security_analysis.md
touch test_mfa.py
```

### Step 3: Password Authentication with bcrypt (45 minutes)

**Assignment Requirement**: Use bcrypt for secure password hashing

```python
import bcrypt
import pyotp
import qrcode
import json
import os
import secrets
import re
from datetime import datetime

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
        """Check password strength according to common rules"""
        issues = []

        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")

        for rule_name, pattern in self.complexity_patterns.items():
            if not re.search(pattern, password):
                issues.append(f"Password must contain at least one {rule_name} character")

        return len(issues) == 0, issues

    def hash_password(self, password):
        """Hash password using bcrypt with proper salt generation"""
        # bcrypt automatically generates salt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash

    def verify_password(self, password, stored_hash):
        """Verify password against bcrypt hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except Exception:
            return False

class SimpleUserStore:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = self.load_users()
        self.password_manager = PasswordManager()

    def load_users(self):
        """Load users from JSON file"""
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                data = json.load(f)
                # Convert password hashes from base64 back to bytes
                for user in data.values():
                    if 'password_hash' in user:
                        import base64
                        user['password_hash'] = base64.b64decode(user['password_hash'])
                return data
        return {}

    def save_users(self):
        """Save users to JSON file"""
        # Convert password hashes to base64 for JSON serialization
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
        """Create new user with password strength checking"""
        if username in self.users:
            return False, "User already exists"

        # Check password strength
        is_strong, issues = self.password_manager.check_password_strength(password)
        if not is_strong:
            return False, issues

        # Hash password with bcrypt
        password_hash = self.password_manager.hash_password(password)

        self.users[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat()
        }

        self.save_users()
        return True, "User created successfully"

    def authenticate_password(self, username, password):
        """Authenticate user with password"""
        if username not in self.users:
            return False, "Invalid credentials"

        user = self.users[username]
        if self.password_manager.verify_password(password, user['password_hash']):
            return True, "Password verified"

        return False, "Invalid credentials"
```

### Step 4: TOTP Implementation with pyotp (45 minutes)

**Assignment Requirement**: Use pyotp library for TOTP generation

```python
class TOTPManager:
    def __init__(self):
        self.window_tolerance = 1  # Allow 1 window (30 seconds) tolerance

    def generate_secret(self):
        """Generate a random base32 secret for TOTP"""
        return pyotp.random_base32()

    def generate_qr_code(self, username, secret, issuer="MFA Demo"):
        """Generate QR code for easy setup with authenticator apps"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )

        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Save QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        filename = f"{username}_qr.png"
        img.save(filename)

        return filename, secret

    def verify_totp(self, secret, token):
        """Verify TOTP token against secret"""
        totp = pyotp.TOTP(secret)
        # Use valid_window for time tolerance (clock synchronization)
        return totp.verify(token, valid_window=self.window_tolerance)

    def get_current_token(self, secret):
        """Get current TOTP token (for testing)"""
        totp = pyotp.TOTP(secret)
        return totp.now()

class BackupCodeManager:
    def __init__(self):
        self.code_length = 8
        self.num_codes = 10

    def generate_codes(self):
        """Generate secure random backup codes"""
        codes = []
        for _ in range(self.num_codes):
            # Generate random hex codes
            code = secrets.token_hex(self.code_length // 2).upper()
            codes.append(code)
        return codes

    def hash_codes(self, codes):
        """Hash backup codes for secure storage"""
        import hashlib
        hashed_codes = []
        for code in codes:
            # Use SHA-256 to hash backup codes
            hash_value = hashlib.sha256(code.encode()).hexdigest()
            hashed_codes.append(hash_value)
        return hashed_codes

    def verify_code(self, input_code, hashed_codes):
        """Verify backup code against hashed versions"""
        import hashlib
        input_hash = hashlib.sha256(input_code.upper().encode()).hexdigest()
        return input_hash in hashed_codes

class SimpleMFA:
    def __init__(self):
        self.user_store = SimpleUserStore()
        self.totp_manager = TOTPManager()
        self.backup_manager = BackupCodeManager()

    def setup_user_mfa(self, username):
        """Set up MFA for existing user"""
        if username not in self.user_store.users:
            return False, "User not found"

        # Generate TOTP secret
        secret = self.totp_manager.generate_secret()

        # Generate backup codes
        backup_codes = self.backup_manager.generate_codes()
        hashed_backup_codes = self.backup_manager.hash_codes(backup_codes)

        # Generate QR code
        qr_filename, _ = self.totp_manager.generate_qr_code(username, secret)

        # Add MFA data to user
        self.user_store.users[username].update({
            'totp_secret': secret,
            'backup_codes': hashed_backup_codes,
            'mfa_enabled': True
        })

        self.user_store.save_users()

        return True, {
            'qr_code': qr_filename,
            'secret': secret,
            'backup_codes': backup_codes  # Show once, then store hashed
        }

    def authenticate_full(self, username, password, totp_token):
        """Full MFA authentication: password + TOTP"""
        # Step 1: Password authentication
        password_ok, message = self.user_store.authenticate_password(username, password)
        if not password_ok:
            return False, message

        # Step 2: TOTP authentication
        user = self.user_store.users[username]
        if not user.get('mfa_enabled'):
            return True, "Password-only authentication (MFA not set up)"

        # Verify TOTP token
        if self.totp_manager.verify_totp(user['totp_secret'], totp_token):
            return True, "Full MFA authentication successful"

        # Check backup codes
        if self.backup_manager.verify_code(totp_token, user['backup_codes']):
            # Remove used backup code
            import hashlib
            used_hash = hashlib.sha256(totp_token.upper().encode()).hexdigest()
            user['backup_codes'].remove(used_hash)
            self.user_store.save_users()

            remaining = len(user['backup_codes'])
            return True, f"Backup code accepted. {remaining} codes remaining."

        return False, "Invalid TOTP token or backup code"
```

### Step 5: Simple Command Line Interface (30 minutes)

**Assignment Requirement**: Test suite for all auth methods

```python
import argparse
import getpass

def main():
    parser = argparse.ArgumentParser(description="Simple MFA Analysis System")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Create user
    create_parser = subparsers.add_parser('create-user', help='Create new user')
    create_parser.add_argument('username', help='Username')

    # Setup MFA
    setup_parser = subparsers.add_parser('setup-mfa', help='Setup MFA for user')
    setup_parser.add_argument('username', help='Username')

    # Test authentication
    auth_parser = subparsers.add_parser('authenticate', help='Test MFA authentication')
    auth_parser.add_argument('username', help='Username')

    # Test individual components
    test_parser = subparsers.add_parser('test', help='Test individual components')
    test_parser.add_argument('component', choices=['password', 'totp', 'backup'],
                           help='Component to test')

    args = parser.parse_args()

    # Initialize MFA system
    mfa = SimpleMFA()

    if args.command == 'create-user':
        password = getpass.getpass("Password: ")
        success, message = mfa.user_store.create_user(args.username, password)

        if success:
            print(f"✅ User {args.username} created successfully!")
        else:
            print(f"❌ Failed to create user: {message}")

    elif args.command == 'setup-mfa':
        success, result = mfa.setup_user_mfa(args.username)

        if success:
            print(f"✅ MFA setup complete for {args.username}")
            print(f"📱 QR code saved as: {result['qr_code']}")
            print(f"🔑 Manual setup key: {result['secret']}")
            print("\n💾 Backup codes (save these securely!):")
            for i, code in enumerate(result['backup_codes'], 1):
                print(f"   {i:2d}. {code}")
        else:
            print(f"❌ MFA setup failed: {result}")

    elif args.command == 'authenticate':
        password = getpass.getpass("Password: ")
        totp_token = input("Enter TOTP code or backup code: ")

        success, message = mfa.authenticate_full(args.username, password, totp_token)

        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ Authentication failed: {message}")

    elif args.command == 'test':
        if args.component == 'password':
            test_password_component(mfa)
        elif args.component == 'totp':
            test_totp_component(mfa)
        elif args.component == 'backup':
            test_backup_component(mfa)

    else:
        parser.print_help()

def test_password_component(mfa):
    """Test password authentication independently"""
    print("🔒 Testing Password Component")

    # Test password strength checking
    weak_passwords = ["123", "password", "12345678"]
    strong_password = "StrongP@ssw0rd123"

    print("\nTesting password strength:")
    for pwd in weak_passwords:
        is_strong, issues = mfa.user_store.password_manager.check_password_strength(pwd)
        print(f"   '{pwd}': {'✅ Strong' if is_strong else '❌ Weak'} - {issues}")

    is_strong, issues = mfa.user_store.password_manager.check_password_strength(strong_password)
    print(f"   '{strong_password}': {'✅ Strong' if is_strong else '❌ Weak'}")

    # Test bcrypt hashing
    print("\nTesting bcrypt hashing:")
    password_hash = mfa.user_store.password_manager.hash_password(strong_password)
    print(f"   Hash generated: {password_hash[:20]}...")

    # Test verification
    verify_result = mfa.user_store.password_manager.verify_password(strong_password, password_hash)
    print(f"   Verification: {'✅ Success' if verify_result else '❌ Failed'}")

def test_totp_component(mfa):
    """Test TOTP component independently"""
    print("📱 Testing TOTP Component")

    # Generate secret and get current token
    secret = mfa.totp_manager.generate_secret()
    current_token = mfa.totp_manager.get_current_token(secret)

    print(f"\nGenerated secret: {secret}")
    print(f"Current TOTP token: {current_token}")

    # Test verification
    verify_result = mfa.totp_manager.verify_totp(secret, current_token)
    print(f"Token verification: {'✅ Success' if verify_result else '❌ Failed'}")

    # Test with wrong token
    wrong_token = "000000"
    verify_wrong = mfa.totp_manager.verify_totp(secret, wrong_token)
    print(f"Wrong token verification: {'✅ Rejected' if not verify_wrong else '❌ Incorrectly accepted'}")

def test_backup_component(mfa):
    """Test backup codes component independently"""
    print("🔑 Testing Backup Codes Component")

    # Generate codes
    codes = mfa.backup_manager.generate_codes()
    print(f"\nGenerated {len(codes)} backup codes:")
    for i, code in enumerate(codes[:3], 1):  # Show first 3
        print(f"   {i}. {code}")
    print("   ...")

    # Test hashing
    hashed_codes = mfa.backup_manager.hash_codes(codes)
    print(f"\nHashed codes for storage: {len(hashed_codes)} entries")

    # Test verification
    test_code = codes[0]
    verify_result = mfa.backup_manager.verify_code(test_code, hashed_codes)
    print(f"Backup code verification: {'✅ Success' if verify_result else '❌ Failed'}")

    # Test with wrong code
    wrong_code = "WRONGCODE"
    verify_wrong = mfa.backup_manager.verify_code(wrong_code, hashed_codes)
    print(f"Wrong backup code verification: {'✅ Rejected' if not verify_wrong else '❌ Incorrectly accepted'}")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: bcrypt import error
**Solution**: Install with `pip install bcrypt`

### Issue: TOTP codes not working
**Causes:**
- Clock synchronization issues
- Typing code too slowly (30-second window)
- Wrong shared secret
**Solution**: Use `valid_window=1` in pyotp verification for time tolerance

### Issue: QR code not scanning
**Solution**: Ensure authenticator app supports TOTP URLs, check image clarity

### Issue: Backup codes not working
**Cause**: Case sensitivity or hashing issues
**Solution**: Convert to uppercase and verify hashing/verification logic

## ✅ Testing Workflow (Assignment Requirements)

```bash
# 1. Test individual components
python mfa_system.py test password
python mfa_system.py test totp
python mfa_system.py test backup

# 2. Create test user
python mfa_system.py create-user testuser

# 3. Setup MFA
python mfa_system.py setup-mfa testuser
# Scan QR code with Google Authenticator

# 4. Test authentication
python mfa_system.py authenticate testuser
# Enter password, then TOTP code from app

# 5. Test backup code authentication
python mfa_system.py authenticate testuser
# Enter password, then one of the backup codes
```

## 📁 Expected File Structure (Assignment Requirements)
```
week04-mfa-analysis/
├── mfa_system.py                 # Your implementation
├── security_analysis.md          # Security analysis report
├── test_mfa.py                   # Test suite
├── README.md                     # Usage documentation
├── users.json                    # User database
└── testuser_qr.png              # Generated QR codes
```

## 📝 Security Analysis Template (5 points)

Create `security_analysis.md` with these sections:

```markdown
# MFA Security Analysis

## Authentication Factor Comparison

### Something You Know (Password)
- **Strength**: Easy to implement, familiar to users
- **Weakness**: Can be guessed, stolen, or forgotten
- **Attack Vectors**: Brute force, dictionary attacks, phishing
- **Best Practices**: Strong complexity rules, bcrypt hashing

### Something You Have (TOTP)
- **Strength**: Time-limited, harder to intercept
- **Weakness**: Device dependency, clock synchronization
- **Attack Vectors**: Device theft, SIM swapping, man-in-the-middle
- **Best Practices**: Secure key storage, time tolerance

### Backup Codes
- **Strength**: Offline recovery option
- **Weakness**: Physical security dependency
- **Attack Vectors**: Theft of stored codes, shoulder surfing
- **Best Practices**: Secure storage, one-time use, hashing

## Real-World MFA Failures

1. **SIM Swapping Attacks**: Attackers transfer victim's phone number
2. **Phishing Attacks**: Fake sites capturing TOTP codes
3. **Device Compromise**: Malware stealing authenticator seeds
4. **Social Engineering**: Tricking support into MFA bypass

## Implementation Best Practices

1. Use established libraries (bcrypt, pyotp)
2. Implement proper time windows for TOTP
3. Store only hashed versions of sensitive data
4. Provide recovery mechanisms (backup codes)
5. Rate limiting and account lockout protection
```

## 🎯 Grading Focus Areas (from assignment)

1. **Password Authentication (5 points)**: bcrypt hashing, salt generation, strength checking
2. **TOTP Implementation (5 points)**: pyotp usage, QR codes, time-window tolerance
3. **Backup Codes (5 points)**: Secure generation, one-time use, hashed storage
4. **Security Analysis (5 points)**: Factor comparison, attack vectors, best practices
5. **Testing & Documentation (5 points)**: Test suite, clear documentation

## 💡 Pro Tips

1. **Focus on Library Usage**: Assignment wants you to use existing libraries properly
2. **Test with Real Apps**: Download Google Authenticator for testing
3. **Security Analysis is Key**: Spend time understanding attack vectors
4. **Keep It Simple**: Don't over-engineer, focus on core requirements
5. **Document Everything**: Clear README and security analysis

## 🔍 Key Concepts to Understand

### Authentication vs. Authorization:
- **Authentication**: Who are you? (identity verification)
- **Authorization**: What can you do? (permission checking)

### MFA Security Properties:
- **Multiple factors** increase security exponentially
- **Independent factors** prevent single points of failure
- **User experience** must balance security and usability

## 🚀 Optional Enhancements

If you finish the core requirements:
- Add rate limiting for failed attempts
- Implement TOTP with different time windows
- Add SMS backup option simulation
- Create web interface instead of CLI

## ⏱️ Time Management

- **Don't build enterprise features**: Focus on assignment requirements
- **Test each component separately**: Use the test functions
- **Security analysis is critical**: Allocate 1 hour for this
- **Use real authenticator apps**: Don't just simulate

## 🔧 Debugging Helpers

**Test TOTP manually:**
```python
import pyotp
secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)
print(f"Secret: {secret}")
print(f"Current token: {totp.now()}")
print(f"Verification: {totp.verify(totp.now())}")
```

**Test bcrypt hashing:**
```python
import bcrypt
password = "test123"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print(f"Hash: {hashed}")
print(f"Verify: {bcrypt.checkpw(password.encode(), hashed)}")
```

**Generate test QR code:**
```python
import pyotp, qrcode
secret = pyotp.random_base32()
uri = pyotp.TOTP(secret).provisioning_uri("testuser", "MFA Demo")
qr = qrcode.make(uri)
qr.save("test_qr.png")
```

Remember: This assignment is about understanding MFA components and their security properties, not building production systems!