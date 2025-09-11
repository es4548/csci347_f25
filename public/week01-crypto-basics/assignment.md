# Week 1 Assignment: Secure Password Vault (Simplified)

**Due**: End of Week 1 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Submit Pull Request URL to Canvas (see submission instructions below)
**Estimated Time**: 5 hours

## 🎯 Assignment Overview

Build a command-line password manager that securely stores website credentials using AES encryption. We'll provide starter code for the cryptographic operations so you can focus on understanding how encryption protects data.

## 📋 Requirements

### Core Functionality (70 points)

Your password vault must implement these features:

#### 1. Master Password Protection (20 points)
- **Use provided encryption functions** with Fernet (AES)
- **Derive key from master password** (starter code provided)
- **Proper error handling** for incorrect passwords

#### 2. Password Storage Operations (30 points)
- **Add new passwords**: `add_password(website, username, password)`
- **Retrieve passwords**: `get_password(website)`
- **List all websites**: `list_websites()`

#### 3. Secure File Storage (20 points)
- **Encrypted vault file** using provided Fernet wrapper
- **Basic file save/load operations**
- **Graceful handling** of missing vault files

### Command-Line Interface (20 points)

Implement a user-friendly CLI with these commands:

```bash
# Create new vault
python password_vault.py init

# Add a password
python password_vault.py add <website> <username> <password>

# Get a password
python password_vault.py get <website>

# List all websites
python password_vault.py list
```

### Security Features (10 points)

- **Input validation** to prevent empty or excessively long inputs
- **Proper error messages** without revealing sensitive information
- **Secure handling of master password** using getpass

## 🔧 Technical Specifications

### Provided Starter Code
```python
# starter_code.py - Copy this into your password_vault.py
from cryptography.fernet import Fernet
import os
import sys
import json
import getpass
import base64

def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """
    Derive an encryption key from a password.
    Returns (key, salt) tuple.
    """
    if salt is None:
        salt = os.urandom(16)
    
    # Simple key derivation (already configured for security)
    key = base64.urlsafe_b64encode(
        (password + salt.hex())[:32].encode().ljust(32, b'0')
    )
    return key, salt

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt string data using Fernet (AES)"""
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using Fernet (AES)"""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()
```

### File Structure
```
password_vault.py          # Main implementation
README.txt                 # Usage instructions and design notes
requirements.txt           # Dependencies (if any additional packages)
```

### Data Format
Design your own secure format for storing encrypted password data. Consider:
- How to store multiple passwords in one encrypted file
- How to handle metadata (website names, usernames)
- How to ensure data integrity

## 📝 Implementation Guide

### 1. Use the Provided Starter Code
Start your `password_vault.py` file by copying the provided encryption functions. These handle the complex cryptography for you.

### 2. Implement Core Functions
```python
def init_vault(master_password):
    """Create a new password vault with the given master password"""
    # Use derive_key_from_password() to create encryption key
    # Create empty vault dictionary
    # Save to file using encrypt_data()

def add_password(website, username, password, master_password):
    """Add a new password entry to the vault"""
    # Load vault using decrypt_data()
    # Add new entry to dictionary
    # Save back to file using encrypt_data()

def get_password(website, master_password):
    """Retrieve password for a website"""
    # Load vault using decrypt_data()
    # Return the password for the website
```

### 3. Error Handling
Your program should handle these common cases:
- **Incorrect master password**: Print "Incorrect master password"
- **Missing vault file**: Print "No vault found. Use 'init' to create one"
- **Website not found**: Print "No password found for [website]"

## 💻 Example Usage

```bash
$ python password_vault.py init
Enter master password: [hidden input]
Confirm master password: [hidden input]
✅ Vault created successfully!

$ python password_vault.py add github.com myusername MySecurePass123!
Enter master password: [hidden input]
✅ Password added for github.com

$ python password_vault.py list
Enter master password: [hidden input]
📋 Stored passwords:
   • github.com (myusername)
   • gmail.com (user@email.com)
   • banking.com (account123)

$ python password_vault.py get github.com
Enter master password: [hidden input]
🔑 github.com credentials:
   Username: myusername
   Password: MySecurePass123!

$ python password_vault.py update github.com NewEvenBetterPass456!
Enter master password: [hidden input]
✅ Password updated for github.com
```

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Points | Focus Area |
|-----------|---------|---------|
| **Encryption Works** | 10 | Passwords are encrypted/decrypted correctly using provided functions |
| **Core Operations** | 10 | Add, retrieve, and list operations work |
| **Error Handling** | 5 | Handles missing files and wrong passwords gracefully |

### Grade Scale
- **23-25 points (A)**: All features work correctly
- **20-22 points (B)**: Most features work, minor issues
- **18-19 points (C)**: Basic functionality works
- **15-17 points (D)**: Some features work
- **Below 15 points (F)**: Major problems

## 🚀 Optional Challenge

If you finish early and want an extra challenge (no bonus points):
- Add a password strength checker that warns about weak passwords
- Implement an update command to change existing passwords
- Add support for password expiration dates

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **Vault initialization creates encrypted file**
- [ ] **Can add and retrieve passwords**
- [ ] **List command shows all stored websites**
- [ ] **Wrong master password shows error message**
- [ ] **Missing vault file handled gracefully**

### Quick Test
```bash
python password_vault.py init
python password_vault.py add github.com user pass123
python password_vault.py list
python password_vault.py get github.com
```

## 📚 Resources and References

### Documentation
- **Cryptography library**: https://cryptography.io/en/latest/
- **PBKDF2 specification**: https://tools.ietf.org/html/rfc2898
- **Python argparse**: https://docs.python.org/3/library/argparse.html

### Security Guidelines
- **OWASP Password Storage**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **NIST Digital Identity Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html

### Simple Code Structure
```python
import argparse
import getpass
import json
import os
# Copy the starter code here

VAULT_FILE = "passwords.vault"

def init_vault(master_password):
    # Create new vault
    pass

def add_password(website, username, password, master_password):
    # Add password to vault
    pass

def get_password(website, master_password):
    # Get password from vault
    pass

def list_websites(master_password):
    # List all websites
    pass

def main():
    parser = argparse.ArgumentParser(description="Password Vault")
    # Handle command line arguments
    pass

if __name__ == "__main__":
    main()
```

## ❓ Frequently Asked Questions

**Q: Can I use additional Python packages?**  
A: Stick to the cryptography library and Python standard library. If you need additional packages, list them in requirements.txt and justify their use in README.txt.

**Q: How should I handle the master password input?**  
A: Use `getpass.getpass()` for hidden password input. Never store the master password in memory longer than necessary.

**Q: What if the vault file gets corrupted?**  
A: Detect corruption (failed decryption, malformed data) and provide a clear error message. Consider implementing a backup/recovery feature for bonus points.

**Q: Should passwords be visible when retrieved?**  
A: Yes, the purpose is to retrieve passwords for use. However, consider security implications and maybe offer a "copy to clipboard" option.

**Q: How complex should the CLI be?**  
A: Focus on functionality over fancy features. A simple, reliable interface is better than a complex, buggy one.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would I trust this program with my real passwords?**
2. **Does it handle all error cases gracefully?**
3. **Is the code clear and well-organized?**
4. **Have I tested it thoroughly on different scenarios?**
5. **Does it follow security best practices learned in the tutorial?**

## 📤 Submission Instructions

### Step 1: Create Pull Request
1. **Push your code** to your forked repository:
   ```bash
   git add .
   git commit -m "Complete Week 1 password vault assignment"
   git push origin week01-assignment
   ```

2. **Create Pull Request** on GitHub:
   - Go to your fork: `https://github.com/YourUsername/CSCI347_f25`
   - Click "Compare & pull request"
   - Write a clear description including:
     - Summary of your implementation
     - Key security decisions made
     - Any challenges encountered
     - Testing approach used
   - Click "Create pull request"

### Step 2: Submit to Canvas
1. **Copy the Pull Request URL** (e.g., `https://github.com/instructor/CSCI347_f25/pull/42`)
2. **Go to Canvas** → Week 1 Assignment
3. **Paste the PR URL** in the submission box
4. **Submit**

### Required Files in Your PR
- `password_vault.py` - Your complete implementation
- `README.md` - Usage instructions and design decisions
- `requirements.txt` - Any additional dependencies (if used)
- `test_examples.txt` - Example usage/testing (optional but recommended)

**Note**: You must submit the PR URL to Canvas for grading. The instructor will review your code via GitHub and provide feedback through both GitHub and Canvas.

---

**Need Help?**
- Review the tutorial materials
- Check Canvas discussions for common issues
- Attend office hours for debugging help
- Use the validation script to check your work

**Good luck!** This assignment will give you hands-on experience with real-world cryptographic applications.