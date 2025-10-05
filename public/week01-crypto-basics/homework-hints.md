# Week 1 Homework Hints: Secure Password Vault

## 🎯 Quick Start Guide (5 hours total)

### Time Breakdown
- **Setup & Understanding**: 1 hour
- **Core Implementation**: 3 hours
- **Testing & Debugging**: 1 hour

## 📋 Step-by-Step Implementation

### Step 1: Set Up Your Environment (15 minutes)
```bash
# Install required library
pip install cryptography

# Create your working directory
mkdir week01-password-vault
cd week01-password-vault

# Create the main file
touch password_vault.py
```

### Step 2: Copy and Understand Starter Code (15 minutes)
Copy the provided starter code into your `password_vault.py` file. **Key understanding points:**

- `derive_key_from_password()` - Converts your master password into an encryption key
- `encrypt_data()` - Secures your password data
- `decrypt_data()` - Retrieves your password data
- These functions handle the complex crypto for you!

### Step 3: Plan Your Data Structure (15 minutes)
Design how you'll store passwords. Hint: Use a simple dictionary:
```python
vault_data = {
    "github.com": {
        "username": "myuser",
        "password": "mypass123"
    },
    "gmail.com": {
        "username": "user@email.com",
        "password": "secure456"
    }
}
```

### Step 4: Implement Core Functions (2 hours)

#### A. Vault Initialization (30 minutes)
```python
def init_vault(master_password):
    """Create a new encrypted vault file"""
    # 1. Create empty vault dictionary
    # 2. Use derive_key_from_password() to get encryption key
    # 3. Use encrypt_data() to encrypt empty vault
    # 4. Save to file (suggest: "passwords.vault")
    # 5. Also save the salt for later use
```

**Hint**: You'll need to save both the encrypted data AND the salt. Consider using JSON format.

#### B. Adding Passwords (45 minutes)
```python
def add_password(website, username, password, master_password):
    """Add a new password to the vault"""
    # 1. Load existing vault using decrypt_data()
    # 2. Add new entry to dictionary
    # 3. Re-encrypt and save
    # 4. Handle case where vault doesn't exist yet
```

**Common Issue**: Make sure to handle the case where the vault file doesn't exist yet.

#### C. Retrieving Passwords (30 minutes)
```python
def get_password(website, master_password):
    """Get password for a specific website"""
    # 1. Load vault using decrypt_data()
    # 2. Look up website in dictionary
    # 3. Return username and password
    # 4. Handle case where website not found
```

#### D. Listing Websites (15 minutes)
```python
def list_websites(master_password):
    """Show all stored websites"""
    # 1. Load vault using decrypt_data()
    # 2. Return list of all websites
    # 3. Don't show actual passwords!
```

### Step 5: Command Line Interface (45 minutes)

Use argparse to handle commands:
```python
def main():
    parser = argparse.ArgumentParser(description="Password Vault")
    parser.add_argument("command", choices=["init", "add", "get", "list"])
    # Add arguments for each command

    args = parser.parse_args()

    if args.command == "init":
        # Get master password with getpass
        # Call init_vault()
    elif args.command == "add":
        # Get master password
        # Call add_password()
    # etc.
```

**Important**: Use `getpass.getpass()` for password input to hide it from screen.

### Step 6: Error Handling (15 minutes)

Add try/catch blocks for:
- Wrong master password (Fernet will raise InvalidToken)
- Missing vault file (FileNotFoundError)
- Website not found (KeyError)

## 🐛 Common Issues & Solutions

### Issue: "InvalidToken" error
**Cause**: Wrong master password or corrupted file
**Solution**: Check your password, or delete vault and start over

### Issue: "FileNotFoundError"
**Cause**: Vault file doesn't exist yet
**Solution**: Check if file exists before trying to load

### Issue: JSON decode error
**Cause**: Corrupted vault file
**Solution**: Add validation when loading data

### Issue: Key derivation problems
**Cause**: Not saving/loading salt correctly
**Solution**: Make sure to save salt with encrypted data

## 📝 File Structure Hints

Recommended file organization:
```
password_vault.py
passwords.vault        # Your encrypted vault (created by program)
README.txt            # Usage instructions
```

## ✅ Testing Checklist

Before submitting, test these scenarios:

1. **Basic Flow**:
   ```bash
   python password_vault.py init
   python password_vault.py add github.com myuser mypass123
   python password_vault.py list
   python password_vault.py get github.com
   ```

2. **Error Cases**:
   - Try to get password before creating vault
   - Try wrong master password
   - Try to get password for non-existent website

3. **Edge Cases**:
   - Empty website name
   - Very long passwords
   - Special characters in passwords

## 🎯 Grading Focus Areas

Your implementation will be graded on:

1. **Encryption Works (10 points)**: Passwords are properly encrypted/decrypted
2. **Core Operations (10 points)**: Add, get, and list functions work
3. **Error Handling (5 points)**: Graceful handling of errors

## 💡 Pro Tips

1. **Start Simple**: Get basic functionality working before adding features
2. **Test Often**: Test each function as you write it
3. **Use the Debugger**: Step through your code to understand how it works
4. **Read Error Messages**: Python error messages are usually helpful
5. **Handle Edge Cases**: Empty inputs, missing files, wrong passwords

## 🚀 Extension Ideas (Optional)

If you finish early:
- Add password strength checking
- Add password generation
- Add backup/restore functionality
- Add password expiration dates

## ⏱️ Time Management

- Don't spend more than 30 minutes on any single function
- If stuck, move to the next part and come back
- Use office hours if you're spending too long on crypto details
- Focus on getting basic functionality working first

## 🔍 Sample Code Snippets

**Loading vault data**:
```python
def load_vault(master_password):
    try:
        with open("passwords.vault", "rb") as f:
            vault_data = json.loads(f.read())

        key, _ = derive_key_from_password(master_password, vault_data["salt"])
        decrypted = decrypt_data(vault_data["data"], key)
        return json.loads(decrypted)
    except FileNotFoundError:
        print("No vault found. Use 'init' to create one")
        return None
```

**Saving vault data**:
```python
def save_vault(vault_dict, master_password, salt):
    vault_json = json.dumps(vault_dict)
    key, _ = derive_key_from_password(master_password, salt)
    encrypted = encrypt_data(vault_json, key)

    vault_file = {
        "salt": salt.hex(),
        "data": encrypted
    }

    with open("passwords.vault", "w") as f:
        json.dump(vault_file, f)
```

Remember: The goal is to understand how encryption protects data, not to become a crypto expert! Focus on using the provided functions correctly.