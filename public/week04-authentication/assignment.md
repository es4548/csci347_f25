# Week 4 Assignment: Multi-Factor Authentication Analysis

**Due**: End of Week 4  
**Points**: 25 points  
**Estimated Time**: 4 hours  
**Submission**: Submit Pull Request URL to Canvas

---
*Updated for Fall 2025*

## 🎯 Assignment Overview

Analyze and implement a simplified MFA system using existing authentication libraries. Focus on understanding different authentication factors and their security properties.

## 📋 Requirements

### Core Implementation (15 points)

#### 1. Password Authentication (5 points)
- Use bcrypt for secure password hashing
- Implement proper salt generation
- Add password strength checking
- Handle authentication attempts securely

#### 2. TOTP Implementation (5 points)
- Use pyotp library for TOTP generation
- Generate QR codes for easy setup
- Implement time-window tolerance
- Test with Google Authenticator

#### 3. Backup Codes (5 points)
- Generate secure random backup codes
- Implement one-time use mechanism
- Store hashed versions only
- Provide recovery workflow

### Security Analysis (5 points)

Write a security analysis covering:
- Comparison of authentication factors (something you know/have/are)
- Attack vectors for each factor
- Best practices for MFA implementation
- Analysis of real-world MFA failures

### Testing and Documentation (5 points)

- Test suite for all auth methods
- Clear usage documentation
- Security considerations document

## 🔧 Starter Code Provided

We provide a template with authentication framework - you just need to implement the core logic.

## Submission

- `mfa_system.py` - Your implementation
- `security_analysis.md` - MFA security analysis
- `test_mfa.py` - Test suite
- `README.md` - Usage documentation
