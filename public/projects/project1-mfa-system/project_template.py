#!/usr/bin/env python3
"""
Enterprise MFA System Template

This template provides the basic structure for implementing a comprehensive
Multi-Factor Authentication system. Students should build upon this foundation
to create a production-ready authentication platform.

Author: CSCI 347 Course Template
Date: Fall 2025
"""

import os
import secrets
import hashlib
import hmac
import time
import qrcode
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

import bcrypt
import pyotp
import jwt
from cryptography.fernet import Fernet


class AuthFactorType(Enum):
    """Types of authentication factors supported by the MFA system"""
    PASSWORD = "password"
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    FIDO2 = "fido2"
    BACKUP_CODE = "backup_code"


class RiskLevel(Enum):
    """Risk assessment levels for adaptive authentication"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class User:
    """User model with MFA capabilities"""
    user_id: str
    username: str
    email: str
    password_hash: str
    phone_number: Optional[str] = None
    totp_secret: Optional[str] = None
    backup_codes: List[str] = None
    is_active: bool = True
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.backup_codes is None:
            self.backup_codes = []


@dataclass
class AuthenticationAttempt:
    """Authentication attempt record for monitoring and analysis"""
    user_id: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    factors_used: List[AuthFactorType]
    success: bool
    risk_level: RiskLevel
    failure_reason: Optional[str] = None
    device_fingerprint: Optional[str] = None
    geolocation: Optional[Dict[str, Any]] = None


class MFASystem:
    """
    Core MFA System Implementation Template
    
    This class provides the foundational structure for implementing
    enterprise-grade multi-factor authentication. Students should
    extend and customize this template based on project requirements.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the MFA system with configuration
        
        Args:
            config: Dictionary containing system configuration
        """
        self.config = config or {}
        self._setup_encryption()
        self._setup_rate_limiting()
        
        # TODO: Initialize database connections
        # TODO: Setup Redis cache for sessions
        # TODO: Configure external API clients (SMS, email)
        
    def _setup_encryption(self):
        """Setup encryption for sensitive data storage"""
        # Generate or load encryption key for sensitive data
        encryption_key = os.environ.get('ENCRYPTION_KEY')
        if not encryption_key:
            # In production, this should be loaded from secure storage
            encryption_key = Fernet.generate_key()
        
        self.cipher_suite = Fernet(encryption_key)
    
    def _setup_rate_limiting(self):
        """Initialize rate limiting mechanisms"""
        # TODO: Implement rate limiting using Redis
        self.rate_limit_attempts = {}
        self.rate_limit_window = 900  # 15 minutes
        self.max_attempts = 5
    
    # ===== USER MANAGEMENT =====
    
    def create_user(self, username: str, email: str, password: str, 
                   phone_number: Optional[str] = None) -> User:
        """
        Create a new user account with secure password storage
        
        Args:
            username: Unique username
            email: User email address
            password: Plain text password (will be hashed)
            phone_number: Optional phone number for SMS MFA
            
        Returns:
            User object with encrypted sensitive data
            
        TODO: Implement the following:
        - Validate username and email uniqueness
        - Enforce password complexity requirements
        - Store user in database
        - Generate initial backup codes
        - Send welcome email with setup instructions
        """
        # Hash the password using bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate unique user ID
        user_id = secrets.token_urlsafe(16)
        
        # Create user object
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash.decode('utf-8'),
            phone_number=phone_number
        )
        
        # Generate backup codes
        user.backup_codes = self._generate_backup_codes()
        
        return user
    
    def authenticate_password(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with username/password (first factor)
        
        Args:
            username: Username or email
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
            
        TODO: Implement the following:
        - Lookup user in database
        - Check account status (active, locked)
        - Verify password against stored hash
        - Update failed attempt counter
        - Implement account lockout policy
        - Log authentication attempts
        """
        # TODO: Retrieve user from database
        # This is a placeholder - implement database lookup
        user = self._get_user_by_username(username)
        
        if not user:
            return None
        
        # Check if account is locked
        if self._is_account_locked(user):
            return None
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Reset failed attempts on successful authentication
            user.failed_attempts = 0
            return user
        else:
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= self.max_attempts:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            return None
    
    # ===== TOTP IMPLEMENTATION =====
    
    def setup_totp(self, user: User) -> Dict[str, Any]:
        """
        Setup TOTP (Time-based One-Time Password) for a user
        
        Args:
            user: User object to setup TOTP for
            
        Returns:
            Dictionary containing TOTP secret and QR code data
            
        TODO: Implement the following:
        - Generate secure TOTP secret
        - Create QR code for authenticator app setup
        - Store encrypted secret in database
        - Return setup information to user
        """
        # Generate TOTP secret
        secret = pyotp.random_base32()
        user.totp_secret = secret
        
        # Create TOTP URI for QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="Enterprise MFA System"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        return {
            'secret': secret,
            'uri': provisioning_uri,
            'qr_code': qr,
            'manual_entry_key': secret
        }
    
    def verify_totp(self, user: User, token: str) -> bool:
        """
        Verify TOTP token for second factor authentication
        
        Args:
            user: User object with TOTP setup
            token: 6-digit TOTP token from authenticator app
            
        Returns:
            True if token is valid, False otherwise
            
        TODO: Implement the following:
        - Validate token format (6 digits)
        - Verify token against user's TOTP secret
        - Implement token replay protection
        - Handle clock skew tolerance
        """
        if not user.totp_secret or not token:
            return False
        
        try:
            totp = pyotp.TOTP(user.totp_secret)
            return totp.verify(token, valid_window=1)  # Allow 1 period tolerance
        except Exception:
            return False
    
    # ===== SMS/EMAIL VERIFICATION =====
    
    def send_verification_code(self, user: User, method: str) -> str:
        """
        Send verification code via SMS or email
        
        Args:
            user: User to send code to
            method: 'sms' or 'email'
            
        Returns:
            Verification code (for testing - remove in production)
            
        TODO: Implement the following:
        - Generate secure random verification code
        - Store code with expiration time in cache
        - Send code via SMS/email API
        - Implement rate limiting for code sending
        - Log verification attempts
        """
        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"
        
        # TODO: Store code in Redis cache with expiration
        # TODO: Send code via SMS/email API
        
        if method == 'sms' and user.phone_number:
            # TODO: Implement SMS sending
            print(f"SMS Code for {user.phone_number}: {code}")
        elif method == 'email':
            # TODO: Implement email sending
            print(f"Email Code for {user.email}: {code}")
        
        return code  # Remove this in production
    
    def verify_code(self, user: User, code: str) -> bool:
        """
        Verify SMS/email verification code
        
        Args:
            user: User object
            code: Verification code provided by user
            
        Returns:
            True if code is valid, False otherwise
            
        TODO: Implement the following:
        - Retrieve stored code from cache
        - Check code expiration
        - Compare provided code with stored code
        - Implement rate limiting for verification attempts
        - Invalidate code after successful verification
        """
        # TODO: Implement code verification from cache
        # This is a placeholder
        return len(code) == 6 and code.isdigit()
    
    # ===== BACKUP CODES =====
    
    def _generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes for account recovery
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            code = f"{secrets.randbelow(100000000):08d}"
            codes.append(code)
        return codes
    
    def verify_backup_code(self, user: User, code: str) -> bool:
        """
        Verify backup code and invalidate it
        
        Args:
            user: User object
            code: Backup code provided by user
            
        Returns:
            True if code is valid, False otherwise
        """
        if code in user.backup_codes:
            user.backup_codes.remove(code)
            return True
        return False
    
    # ===== RISK ASSESSMENT =====
    
    def assess_risk(self, user: User, request_context: Dict[str, Any]) -> RiskLevel:
        """
        Assess risk level for authentication attempt
        
        Args:
            user: User attempting authentication
            request_context: Request information (IP, user agent, etc.)
            
        Returns:
            Risk level for the authentication attempt
            
        TODO: Implement risk factors:
        - Unknown device/location
        - Unusual login times
        - Failed attempt patterns
        - Velocity-based detection
        - Device fingerprinting
        """
        risk_score = 0
        
        # Check for new IP address
        # TODO: Compare with user's historical IPs
        
        # Check login time patterns
        # TODO: Analyze user's typical login times
        
        # Check failed attempts
        if user.failed_attempts > 0:
            risk_score += user.failed_attempts * 10
        
        # Convert score to risk level
        if risk_score >= 50:
            return RiskLevel.CRITICAL
        elif risk_score >= 30:
            return RiskLevel.HIGH
        elif risk_score >= 15:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    # ===== SESSION MANAGEMENT =====
    
    def create_session(self, user: User, device_info: Dict[str, Any]) -> str:
        """
        Create secure session token after successful authentication
        
        Args:
            user: Authenticated user
            device_info: Device information for session tracking
            
        Returns:
            JWT session token
            
        TODO: Implement the following:
        - Generate JWT with appropriate claims
        - Set token expiration based on risk level
        - Store session information in Redis
        - Implement device fingerprinting
        """
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24),
            'device_fingerprint': device_info.get('fingerprint', 'unknown')
        }
        
        # TODO: Use secure secret key from environment
        secret_key = os.environ.get('JWT_SECRET_KEY', 'dev-key-change-me')
        
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        # TODO: Store session in Redis cache
        
        return token
    
    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate session token and return user information
        
        Args:
            token: JWT session token
            
        Returns:
            Decoded token payload if valid, None otherwise
        """
        try:
            secret_key = os.environ.get('JWT_SECRET_KEY', 'dev-key-change-me')
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            
            # TODO: Check if session exists in Redis
            # TODO: Validate device fingerprint
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    # ===== HELPER METHODS =====
    
    def _get_user_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve user from database by username or email
        
        TODO: Implement database query
        """
        # Placeholder - implement database lookup
        return None
    
    def _is_account_locked(self, user: User) -> bool:
        """Check if user account is currently locked"""
        if user.locked_until is None:
            return False
        return datetime.utcnow() < user.locked_until
    
    def _log_authentication_attempt(self, attempt: AuthenticationAttempt):
        """
        Log authentication attempt for monitoring and analysis
        
        TODO: Implement logging to database and/or logging service
        """
        # Placeholder for logging implementation
        print(f"Auth attempt: {attempt}")


# ===== EXAMPLE USAGE =====

def main():
    """
    Example usage of the MFA system
    This demonstrates the basic flow for user registration and authentication
    """
    print("Enterprise MFA System Template")
    print("=" * 50)
    
    # Initialize MFA system
    mfa_system = MFASystem()
    
    # Create a new user
    user = mfa_system.create_user(
        username="testuser",
        email="test@example.com",
        password="SecurePassword123!",
        phone_number="+1234567890"
    )
    
    print(f"Created user: {user.username}")
    print(f"Backup codes: {user.backup_codes[:3]}...")  # Show first 3 codes
    
    # Setup TOTP
    totp_setup = mfa_system.setup_totp(user)
    print(f"TOTP Secret: {totp_setup['secret']}")
    print("Scan QR code with authenticator app (QR code would be displayed here)")
    
    # Simulate authentication flow
    print("\n--- Authentication Flow ---")
    
    # First factor: Password
    auth_user = mfa_system.authenticate_password("testuser", "SecurePassword123!")
    if auth_user:
        print("✓ Password authentication successful")
        
        # Second factor: TOTP (simulate user entering code)
        # In real implementation, user would enter code from authenticator app
        totp = pyotp.TOTP(user.totp_secret)
        current_token = totp.now()
        
        if mfa_system.verify_totp(user, current_token):
            print("✓ TOTP verification successful")
            
            # Create session
            device_info = {
                'fingerprint': 'test_device_fingerprint',
                'user_agent': 'Test Browser'
            }
            
            session_token = mfa_system.create_session(user, device_info)
            print(f"✓ Session created: {session_token[:50]}...")
            
            # Validate session
            session_data = mfa_system.validate_session(session_token)
            if session_data:
                print("✓ Session validation successful")
                print(f"  User ID: {session_data['user_id']}")
                print(f"  Username: {session_data['username']}")
            
        else:
            print("✗ TOTP verification failed")
    else:
        print("✗ Password authentication failed")


if __name__ == "__main__":
    main()