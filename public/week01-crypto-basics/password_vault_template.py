#!/usr/bin/env python3
"""
Password Vault Template - Week 1 Assignment
CSCI 347 - Network Security and Digital Forensics

This template provides the basic structure for your password vault.
Fill in the TODO sections to complete the assignment.

Student: [Your Name Here - CSCI347_f25]
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
import argparse
import sys

class PasswordVault:
    """Secure password storage using encryption"""
    
    def __init__(self, vault_file="passwords.vault"):
        self.vault_file = vault_file
        self.master_key = None
        
    def setup_vault(self, master_password):
        """Initialize the vault with a master password"""
        # TODO: Implement master password setup
        # Hint: You'll need to derive a key from the password using PBKDF2
        # Steps:
        # 1. Generate a salt (random bytes)
        # 2. Use PBKDF2 to derive key from master_password + salt  
        # 3. Store the salt (you'll need it later)
        # 4. Set self.master_key
        
        print("🔧 TODO: Implement setup_vault method")
        pass
    
    def unlock_vault(self, master_password):
        """Unlock the vault using master password"""
        # TODO: Implement vault unlocking
        # Hint: You'll need the stored salt to recreate the key
        # Steps:
        # 1. Load the salt from storage
        # 2. Derive the same key using master_password + salt
        # 3. Set self.master_key
        # 4. Return True if successful, False if wrong password
        
        print("🔧 TODO: Implement unlock_vault method")
        return False
    
    def add_password(self, service, username, password):
        """Add a new password entry"""
        if not self.master_key:
            print("❌ Vault is locked. Unlock first.")
            return False
            
        # TODO: Implement password storage
        # Hint: Encrypt the password before storing
        # Steps:
        # 1. Load existing passwords (or start with empty dict)
        # 2. Create entry with service, username, encrypted password
        # 3. Save back to vault file
        
        print(f"🔧 TODO: Add password for {service}")
        return True
    
    def get_password(self, service):
        """Retrieve and decrypt a password"""
        if not self.master_key:
            print("❌ Vault is locked. Unlock first.")
            return None
            
        # TODO: Implement password retrieval
        # Hint: Load and decrypt the stored password
        # Steps:
        # 1. Load vault data
        # 2. Find the service entry
        # 3. Decrypt the password
        # 4. Return the decrypted password
        
        print(f"🔧 TODO: Get password for {service}")
        return None
    
    def list_services(self):
        """List all stored services"""
        # TODO: Implement service listing
        # Hint: Load vault data and return list of service names
        
        print("🔧 TODO: List all services")
        return []
    
    def _derive_key(self, password, salt):
        """Helper: Derive encryption key from password"""
        # TODO: Implement PBKDF2 key derivation
        # Hint: Use PBKDF2HMAC with SHA256, 100000 iterations
        
        print("🔧 TODO: Implement key derivation")
        return None
    
    def _load_vault_data(self):
        """Helper: Load vault data from file"""
        try:
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"❌ Error loading vault: {e}")
            return {}
    
    def _save_vault_data(self, data):
        """Helper: Save vault data to file"""
        try:
            with open(self.vault_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"❌ Error saving vault: {e}")
            return False

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Secure Password Vault")
    parser.add_argument('command', choices=['init', 'add', 'get', 'list'], 
                       help='Command to execute')
    parser.add_argument('--service', help='Service name')
    parser.add_argument('--username', help='Username for service')
    parser.add_argument('--password', help='Password for service')
    
    args = parser.parse_args()
    vault = PasswordVault()
    
    if args.command == 'init':
        # TODO: Implement init command
        # Hint: Ask for master password and call setup_vault
        print("🔧 TODO: Implement init command")
        
    elif args.command == 'add':
        # TODO: Implement add command
        # Hint: Unlock vault, then add the password
        print("🔧 TODO: Implement add command")
        
    elif args.command == 'get':
        # TODO: Implement get command  
        # Hint: Unlock vault, then retrieve password
        print("🔧 TODO: Implement get command")
        
    elif args.command == 'list':
        # TODO: Implement list command
        # Hint: Unlock vault, then list services
        print("🔧 TODO: Implement list command")

if __name__ == "__main__":
    main()

# SCAFFOLDING HINTS FOR STRUGGLING STUDENTS:
#
# 1. START SIMPLE: Get the basic class structure working first
# 2. USE PRINT STATEMENTS: Add lots of print() to see what's happening
# 3. TEST EACH METHOD: Write small test code to verify each method works
# 4. DON'T PANIC: It's okay if you don't understand every crypto detail
# 5. ASK FOR HELP: Post questions in Canvas discussions
#
# EXAMPLE TESTING CODE:
# vault = PasswordVault()
# vault.setup_vault("test123")
# vault.add_password("github", "myuser", "mypass")
# print(vault.get_password("github"))