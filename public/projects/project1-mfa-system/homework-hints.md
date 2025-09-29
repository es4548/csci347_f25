# Project 1 Homework Hints: Enterprise MFA System

## Time Breakdown (2 weeks, ~30-40 hours total)

### Week 1 (20 hours)
- **Day 1-2 (6 hours)**: Project setup, architecture design, database schema
- **Day 3-4 (8 hours)**: Core password authentication and session management
- **Day 5-7 (6 hours)**: TOTP implementation and QR code generation

### Week 2 (15-20 hours)
- **Day 8-10 (8 hours)**: SMS/Email verification and backup codes
- **Day 11-12 (5 hours)**: Security features (rate limiting, risk assessment)
- **Day 13-14 (7 hours)**: Testing, documentation, and demo preparation

## Step-by-Step Implementation Guide

### Phase 1: Project Setup and Architecture (6 hours)

#### 1.1 Environment Setup (2 hours)
```bash
# Create project structure
mkdir -p project1-mfa-system/{src/{auth,api,web,models,utils,config},tests,docs,scripts}
cd project1-mfa-system

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install core dependencies
pip install fastapi uvicorn[standard] sqlalchemy psycopg2-binary
pip install passlib[bcrypt] python-jose[cryptography] pyotp qrcode[pil]
pip install redis pytest pytest-cov black pylint mypy
pip install python-multipart jinja2 python-dotenv

# Create requirements.txt
pip freeze > requirements.txt
```

#### 1.2 Database Setup (2 hours)
```python
# src/models/database.py
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/mfa_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    totp_secret = Column(String(32), nullable=True)
    backup_codes = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    session_token = Column(String(255), unique=True, nullable=False)
    device_fingerprint = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    event_type = Column(String(50), nullable=False)  # login, logout, failed_auth, etc.
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    details = Column(Text, nullable=True)  # JSON string
    risk_score = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
```

#### 1.3 Configuration Management (2 hours)
```python
# src/config/settings.py
from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql://user:password@localhost/mfa_db"

    # Security
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Rate Limiting
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    # TOTP Settings
    totp_issuer: str = "MFA Demo App"
    totp_window: int = 1

    # SMS/Email (Mock for demo)
    sms_provider: str = "mock"
    email_provider: str = "mock"

    # Redis for caching
    redis_url: str = "redis://localhost:6379"

    class Config:
        env_file = ".env"

settings = Settings()
```

### Phase 2: Core Authentication (8 hours)

#### 2.1 Password Authentication (4 hours)
```python
# src/auth/password.py
from passlib.context import CryptContext
from passlib.hash import bcrypt
import re
from typing import Optional

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class PasswordValidator:
    @staticmethod
    def validate_password(password: str) -> tuple[bool, list[str]]:
        """Validate password complexity"""
        errors = []

        if len(password) < 12:
            errors.append("Password must be at least 12 characters long")

        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")

        # Check for common passwords (implement blacklist)
        common_passwords = ["password123", "admin123", "123456789"]
        if password.lower() in common_passwords:
            errors.append("Password is too common")

        return len(errors) == 0, errors

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

# src/auth/authentication.py
from sqlalchemy.orm import Session
from src.models.database import User, SecurityEvent
from src.auth.password import PasswordValidator
from datetime import datetime, timedelta
import hashlib

class AuthenticationService:
    def __init__(self, db: Session):
        self.db = db
        self.password_validator = PasswordValidator()

    def register_user(self, username: str, email: str, password: str) -> tuple[bool, str]:
        """Register a new user with password validation"""
        # Check if user exists
        if self.db.query(User).filter(User.username == username).first():
            return False, "Username already exists"

        if self.db.query(User).filter(User.email == email).first():
            return False, "Email already exists"

        # Validate password
        is_valid, errors = self.password_validator.validate_password(password)
        if not is_valid:
            return False, "; ".join(errors)

        # Create user
        password_hash = self.password_validator.hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )

        self.db.add(user)
        self.db.commit()

        # Log security event
        self._log_security_event(user.id, "user_registered", {})

        return True, "User registered successfully"

    def authenticate_password(self, username: str, password: str, ip_address: str) -> tuple[bool, Optional[User], str]:
        """Authenticate user with password"""
        user = self.db.query(User).filter(User.username == username).first()

        if not user:
            self._log_security_event(None, "login_failed", {"reason": "user_not_found", "username": username}, ip_address)
            return False, None, "Invalid credentials"

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            self._log_security_event(user.id, "login_blocked", {"reason": "account_locked"}, ip_address)
            return False, None, f"Account locked until {user.locked_until}"

        # Verify password
        if not self.password_validator.verify_password(password, user.password_hash):
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= 5:  # settings.max_login_attempts
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)

            self.db.commit()
            self._log_security_event(user.id, "login_failed", {"reason": "invalid_password"}, ip_address)
            return False, None, "Invalid credentials"

        # Reset failed attempts on successful authentication
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        self.db.commit()

        self._log_security_event(user.id, "password_auth_success", {}, ip_address)
        return True, user, "Password authentication successful"

    def _log_security_event(self, user_id: Optional[int], event_type: str, details: dict, ip_address: str = None):
        """Log security events for auditing"""
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            details=str(details),
            timestamp=datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()
```

#### 2.2 JWT Session Management (4 hours)
```python
# src/auth/jwt_handler.py
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from src.config.settings import settings

class JWTHandler:
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

        to_encode.update({"exp": expire, "iat": datetime.utcnow()})

        encoded_jwt = jwt.encode(
            to_encode,
            settings.secret_key,
            algorithm=settings.algorithm
        )
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=[settings.algorithm]
            )
            return payload
        except JWTError:
            return None

    @staticmethod
    def create_session_token(user_id: int, device_fingerprint: str = None) -> str:
        """Create session token with device info"""
        payload = {
            "user_id": user_id,
            "device_fingerprint": device_fingerprint,
            "type": "session"
        }
        return JWTHandler.create_access_token(payload)

# src/auth/session.py
from sqlalchemy.orm import Session
from src.models.database import UserSession
from src.auth.jwt_handler import JWTHandler
from datetime import datetime, timedelta
import hashlib

class SessionManager:
    def __init__(self, db: Session):
        self.db = db

    def create_session(self, user_id: int, ip_address: str, user_agent: str) -> str:
        """Create new user session"""
        # Generate device fingerprint
        device_data = f"{ip_address}:{user_agent}"
        device_fingerprint = hashlib.sha256(device_data.encode()).hexdigest()[:32]

        # Create session token
        session_token = JWTHandler.create_session_token(user_id, device_fingerprint)

        # Store session in database
        session = UserSession(
            user_id=user_id,
            session_token=session_token,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(minutes=30)
        )

        self.db.add(session)
        self.db.commit()

        return session_token

    def validate_session(self, session_token: str) -> tuple[bool, Optional[int]]:
        """Validate session token and return user_id if valid"""
        # Verify JWT token
        payload = JWTHandler.verify_token(session_token)
        if not payload:
            return False, None

        # Check session in database
        session = self.db.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()

        if not session:
            return False, None

        return True, session.user_id

    def invalidate_session(self, session_token: str):
        """Invalidate a session"""
        session = self.db.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()

        if session:
            session.is_active = False
            self.db.commit()
```

### Phase 3: TOTP Implementation (6 hours)

#### 3.1 TOTP Service (4 hours)
```python
# src/auth/totp.py
import pyotp
import qrcode
from io import BytesIO
import base64
from typing import Tuple, Optional
from src.config.settings import settings

class TOTPService:
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()

    @staticmethod
    def generate_qr_code(secret: str, username: str) -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=settings.totp_issuer
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)

        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=settings.totp_window)

    @staticmethod
    def get_current_totp(secret: str) -> str:
        """Get current TOTP token (for testing)"""
        totp = pyotp.TOTP(secret)
        return totp.now()

# src/auth/mfa.py
from sqlalchemy.orm import Session
from src.models.database import User, SecurityEvent
from src.auth.totp import TOTPService
import json
import secrets
from datetime import datetime

class MFAService:
    def __init__(self, db: Session):
        self.db = db
        self.totp_service = TOTPService()

    def setup_totp(self, user_id: int) -> tuple[bool, str, str]:
        """Setup TOTP for user"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False, "", "User not found"

        # Generate new secret
        secret = self.totp_service.generate_secret()

        # Generate QR code
        qr_code = self.totp_service.generate_qr_code(secret, user.username)

        # Store secret (temporarily, until verified)
        user.totp_secret = secret
        self.db.commit()

        # Log security event
        self._log_security_event(user_id, "totp_setup_initiated", {})

        return True, qr_code, "TOTP setup initiated. Scan QR code with authenticator app."

    def verify_totp_setup(self, user_id: int, token: str) -> tuple[bool, str]:
        """Verify TOTP setup with first token"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user or not user.totp_secret:
            return False, "TOTP not set up"

        if self.totp_service.verify_totp(user.totp_secret, token):
            # Generate backup codes
            backup_codes = self._generate_backup_codes()
            user.backup_codes = json.dumps(backup_codes)
            self.db.commit()

            self._log_security_event(user_id, "totp_setup_completed", {})

            return True, f"TOTP setup completed. Backup codes: {', '.join(backup_codes)}"
        else:
            return False, "Invalid TOTP token"

    def verify_totp(self, user_id: int, token: str) -> tuple[bool, str]:
        """Verify TOTP token for authentication"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user or not user.totp_secret:
            return False, "TOTP not set up"

        # Check if it's a backup code
        if self._verify_backup_code(user, token):
            self._log_security_event(user_id, "backup_code_used", {"code": token[:4] + "****"})
            return True, "Backup code verified"

        # Verify TOTP token
        if self.totp_service.verify_totp(user.totp_secret, token):
            self._log_security_event(user_id, "totp_verified", {})
            return True, "TOTP verified"
        else:
            self._log_security_event(user_id, "totp_failed", {})
            return False, "Invalid TOTP token"

    def _generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate backup codes"""
        codes = []
        for _ in range(count):
            code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes

    def _verify_backup_code(self, user: User, code: str) -> bool:
        """Verify and consume backup code"""
        if not user.backup_codes:
            return False

        backup_codes = json.loads(user.backup_codes)
        if code in backup_codes:
            # Remove used code
            backup_codes.remove(code)
            user.backup_codes = json.dumps(backup_codes)
            self.db.commit()
            return True

        return False

    def _log_security_event(self, user_id: int, event_type: str, details: dict):
        """Log security events"""
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            details=str(details),
            timestamp=datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()
```

#### 3.2 QR Code Generation (2 hours)
```python
# src/web/templates/totp_setup.html
<!DOCTYPE html>
<html>
<head>
    <title>TOTP Setup - MFA Demo</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        .qr-container { text-align: center; margin: 20px 0; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 10px; font-size: 16px; border: 1px solid #ddd; }
        button { background: #007bff; color: white; padding: 12px 24px; border: none; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .alert { padding: 12px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <h1>Set Up Two-Factor Authentication</h1>

    <div class="instructions">
        <h3>Step 1: Install an Authenticator App</h3>
        <p>Download one of these apps on your phone:</p>
        <ul>
            <li>Google Authenticator</li>
            <li>Microsoft Authenticator</li>
            <li>Authy</li>
            <li>1Password</li>
        </ul>

        <h3>Step 2: Scan the QR Code</h3>
        <p>Open your authenticator app and scan this QR code:</p>
    </div>

    <div class="qr-container">
        <img src="{{ qr_code }}" alt="TOTP QR Code" style="max-width: 300px;">
        <p><strong>Secret Key:</strong> {{ secret }}</p>
        <p><small>(Use this if you can't scan the QR code)</small></p>
    </div>

    <form method="POST" action="/totp/verify-setup">
        <div class="form-group">
            <label for="token">Step 3: Enter the 6-digit code from your app:</label>
            <input type="text" id="token" name="token" maxlength="6" pattern="[0-9]{6}" required>
        </div>

        <button type="submit">Verify and Complete Setup</button>
    </form>

    {% if message %}
    <div class="alert alert-{{ 'success' if success else 'error' }}">
        {{ message }}
    </div>
    {% endif %}

    <div style="margin-top: 30px;">
        <h3>Important Notes:</h3>
        <ul>
            <li>Keep your authenticator app secure</li>
            <li>You'll receive backup codes after verification</li>
            <li>Store backup codes in a safe place</li>
            <li>Each code can only be used once</li>
        </ul>
    </div>
</body>
</html>
```

### Phase 4: SMS/Email Verification (8 hours)

#### 4.1 Verification Service (4 hours)
```python
# src/auth/verification.py
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session
import redis
import json

class VerificationService:
    def __init__(self, db: Session, redis_client=None):
        self.db = db
        self.redis = redis_client or redis.Redis.from_url("redis://localhost:6379")

    def generate_verification_code(self, length: int = 6) -> str:
        """Generate numeric verification code"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))

    def send_sms_code(self, phone_number: str, user_id: int) -> Tuple[bool, str]:
        """Send SMS verification code (mock implementation)"""
        code = self.generate_verification_code()

        # Store in Redis with 5-minute expiration
        key = f"sms_code:{user_id}:{phone_number}"
        self.redis.setex(key, 300, code)  # 5 minutes

        # Mock SMS sending (in production, use Twilio, AWS SNS, etc.)
        print(f"SMS Code for {phone_number}: {code}")

        # Log for demo purposes
        self._log_verification_attempt(user_id, "sms", phone_number)

        return True, f"SMS code sent to {phone_number}"

    def send_email_code(self, email: str, user_id: int) -> Tuple[bool, str]:
        """Send email verification code (mock implementation)"""
        code = self.generate_verification_code()

        # Store in Redis with 10-minute expiration
        key = f"email_code:{user_id}:{email}"
        self.redis.setex(key, 600, code)  # 10 minutes

        # Mock email sending (in production, use SendGrid, AWS SES, etc.)
        print(f"Email Code for {email}: {code}")

        # Log for demo purposes
        self._log_verification_attempt(user_id, "email", email)

        return True, f"Email code sent to {email}"

    def verify_sms_code(self, phone_number: str, user_id: int, code: str) -> Tuple[bool, str]:
        """Verify SMS code"""
        key = f"sms_code:{user_id}:{phone_number}"
        stored_code = self.redis.get(key)

        if not stored_code:
            return False, "Code expired or invalid"

        if stored_code.decode() == code:
            # Remove code after successful verification
            self.redis.delete(key)
            self._log_verification_success(user_id, "sms", phone_number)
            return True, "SMS code verified"
        else:
            self._log_verification_failure(user_id, "sms", phone_number)
            return False, "Invalid code"

    def verify_email_code(self, email: str, user_id: int, code: str) -> Tuple[bool, str]:
        """Verify email code"""
        key = f"email_code:{user_id}:{email}"
        stored_code = self.redis.get(key)

        if not stored_code:
            return False, "Code expired or invalid"

        if stored_code.decode() == code:
            # Remove code after successful verification
            self.redis.delete(key)
            self._log_verification_success(user_id, "email", email)
            return True, "Email code verified"
        else:
            self._log_verification_failure(user_id, "email", email)
            return False, "Invalid code"

    def _log_verification_attempt(self, user_id: int, method: str, contact: str):
        """Log verification attempt"""
        from src.models.database import SecurityEvent
        event = SecurityEvent(
            user_id=user_id,
            event_type=f"{method}_verification_sent",
            details=json.dumps({"contact": contact}),
            timestamp=datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()

    def _log_verification_success(self, user_id: int, method: str, contact: str):
        """Log successful verification"""
        from src.models.database import SecurityEvent
        event = SecurityEvent(
            user_id=user_id,
            event_type=f"{method}_verification_success",
            details=json.dumps({"contact": contact}),
            timestamp=datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()

    def _log_verification_failure(self, user_id: int, method: str, contact: str):
        """Log failed verification"""
        from src.models.database import SecurityEvent
        event = SecurityEvent(
            user_id=user_id,
            event_type=f"{method}_verification_failed",
            details=json.dumps({"contact": contact}),
            timestamp=datetime.utcnow()
        )
        self.db.add(event)
        self.db.commit()
```

#### 4.2 Complete MFA Flow (4 hours)
```python
# src/auth/complete_mfa.py
from sqlalchemy.orm import Session
from src.auth.authentication import AuthenticationService
from src.auth.mfa import MFAService
from src.auth.verification import VerificationService
from src.auth.session import SessionManager
from typing import Dict, Any, Optional

class CompleteMFAService:
    def __init__(self, db: Session):
        self.db = db
        self.auth_service = AuthenticationService(db)
        self.mfa_service = MFAService(db)
        self.verification_service = VerificationService(db)
        self.session_manager = SessionManager(db)

    def initiate_login(self, username: str, password: str, ip_address: str) -> Dict[str, Any]:
        """Initiate login process with password"""
        success, user, message = self.auth_service.authenticate_password(username, password, ip_address)

        if not success:
            return {
                "success": False,
                "message": message,
                "next_step": None
            }

        # Check what MFA methods are available
        mfa_methods = self._get_available_mfa_methods(user.id)

        if not mfa_methods:
            # No MFA set up, complete login
            session_token = self.session_manager.create_session(user.id, ip_address, "")
            return {
                "success": True,
                "message": "Login successful",
                "session_token": session_token,
                "next_step": None,
                "user_id": user.id
            }

        # Store partial login state
        partial_login_key = f"partial_login:{user.id}"
        self.verification_service.redis.setex(partial_login_key, 600, "password_verified")

        return {
            "success": True,
            "message": "Password verified. Choose MFA method.",
            "next_step": "mfa",
            "available_methods": mfa_methods,
            "user_id": user.id
        }

    def verify_mfa_totp(self, user_id: int, token: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Verify TOTP token and complete login"""
        # Check partial login state
        if not self._check_partial_login(user_id):
            return {"success": False, "message": "Invalid session"}

        success, message = self.mfa_service.verify_totp(user_id, token)

        if success:
            # Complete login
            session_token = self.session_manager.create_session(user_id, ip_address, user_agent)
            self._clear_partial_login(user_id)

            return {
                "success": True,
                "message": "Login successful",
                "session_token": session_token
            }
        else:
            return {"success": False, "message": message}

    def send_sms_verification(self, user_id: int, phone_number: str) -> Dict[str, Any]:
        """Send SMS verification code"""
        if not self._check_partial_login(user_id):
            return {"success": False, "message": "Invalid session"}

        success, message = self.verification_service.send_sms_code(phone_number, user_id)
        return {"success": success, "message": message}

    def verify_sms_code(self, user_id: int, phone_number: str, code: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Verify SMS code and complete login"""
        if not self._check_partial_login(user_id):
            return {"success": False, "message": "Invalid session"}

        success, message = self.verification_service.verify_sms_code(phone_number, user_id, code)

        if success:
            session_token = self.session_manager.create_session(user_id, ip_address, user_agent)
            self._clear_partial_login(user_id)

            return {
                "success": True,
                "message": "Login successful",
                "session_token": session_token
            }
        else:
            return {"success": False, "message": message}

    def _get_available_mfa_methods(self, user_id: int) -> list[str]:
        """Get available MFA methods for user"""
        from src.models.database import User
        user = self.db.query(User).filter(User.id == user_id).first()

        methods = []
        if user.totp_secret:
            methods.append("totp")

        # In a real app, you'd check if phone/email are verified
        methods.extend(["sms", "email"])

        return methods

    def _check_partial_login(self, user_id: int) -> bool:
        """Check if user has partial login state"""
        key = f"partial_login:{user_id}"
        return self.verification_service.redis.exists(key)

    def _clear_partial_login(self, user_id: int):
        """Clear partial login state"""
        key = f"partial_login:{user_id}"
        self.verification_service.redis.delete(key)
```

### Phase 5: Security Features (5 hours)

#### 5.1 Rate Limiting (3 hours)
```python
# src/auth/rate_limiter.py
import redis
from datetime import datetime, timedelta
from typing import Tuple, Optional

class RateLimiter:
    def __init__(self, redis_client=None):
        self.redis = redis_client or redis.Redis.from_url("redis://localhost:6379")

    def check_rate_limit(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int, int]:
        """
        Check if action is within rate limit
        Returns: (allowed, current_count, reset_time)
        """
        current_time = int(datetime.utcnow().timestamp())
        window_start = current_time - window_seconds

        # Remove old entries
        self.redis.zremrangebyscore(key, 0, window_start)

        # Count current entries
        current_count = self.redis.zcard(key)

        if current_count >= limit:
            # Get oldest entry to calculate reset time
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            reset_time = int(oldest[0][1]) + window_seconds if oldest else current_time + window_seconds
            return False, current_count, reset_time

        # Add current request
        self.redis.zadd(key, {str(current_time): current_time})
        self.redis.expire(key, window_seconds)

        reset_time = current_time + window_seconds
        return True, current_count + 1, reset_time

    def check_login_rate_limit(self, ip_address: str) -> Tuple[bool, str]:
        """Check login rate limit for IP address"""
        key = f"login_attempts:{ip_address}"
        allowed, count, reset_time = self.check_rate_limit(key, 10, 300)  # 10 attempts per 5 minutes

        if not allowed:
            reset_datetime = datetime.fromtimestamp(reset_time)
            return False, f"Too many login attempts. Try again after {reset_datetime.strftime('%H:%M:%S')}"

        return True, f"Login attempt {count}/10"

    def check_mfa_rate_limit(self, user_id: int) -> Tuple[bool, str]:
        """Check MFA verification rate limit"""
        key = f"mfa_attempts:{user_id}"
        allowed, count, reset_time = self.check_rate_limit(key, 5, 300)  # 5 attempts per 5 minutes

        if not allowed:
            reset_datetime = datetime.fromtimestamp(reset_time)
            return False, f"Too many MFA attempts. Try again after {reset_datetime.strftime('%H:%M:%S')}"

        return True, f"MFA attempt {count}/5"

# src/auth/risk_assessment.py
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from src.models.database import SecurityEvent, UserSession

class RiskAssessment:
    def __init__(self, db: Session, redis_client=None):
        self.db = db
        self.redis = redis_client or redis.Redis.from_url("redis://localhost:6379")

    def calculate_risk_score(self, user_id: int, ip_address: str, user_agent: str) -> int:
        """Calculate risk score for login attempt (0-100)"""
        risk_score = 0

        # Check for new device
        if self._is_new_device(user_id, ip_address, user_agent):
            risk_score += 30

        # Check for unusual location (mock implementation)
        if self._is_unusual_location(user_id, ip_address):
            risk_score += 25

        # Check time of access
        risk_score += self._calculate_time_risk(user_id)

        # Check recent failed attempts
        risk_score += self._calculate_failure_risk(user_id, ip_address)

        # Check for concurrent sessions
        if self._has_concurrent_sessions(user_id):
            risk_score += 10

        return min(risk_score, 100)

    def _is_new_device(self, user_id: int, ip_address: str, user_agent: str) -> bool:
        """Check if this is a new device for the user"""
        device_data = f"{ip_address}:{user_agent}"
        device_fingerprint = hashlib.sha256(device_data.encode()).hexdigest()[:32]

        # Check if device has been used before
        existing_session = self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.device_fingerprint == device_fingerprint
        ).first()

        return existing_session is None

    def _is_unusual_location(self, user_id: int, ip_address: str) -> bool:
        """Check if IP address is from unusual location (mock)"""
        # In production, use IP geolocation service
        key = f"user_locations:{user_id}"
        known_locations = self.redis.smembers(key)

        # Mock: assume locations based on IP ranges
        location = self._get_mock_location(ip_address)

        if location.encode() not in known_locations:
            # Add to known locations
            self.redis.sadd(key, location)
            self.redis.expire(key, 86400 * 30)  # 30 days
            return True

        return False

    def _get_mock_location(self, ip_address: str) -> str:
        """Mock location detection"""
        # Simple mock based on IP
        if ip_address.startswith("192.168") or ip_address.startswith("10."):
            return "Local Network"
        elif ip_address.startswith("127."):
            return "Localhost"
        else:
            # Hash IP to get consistent mock location
            ip_hash = hashlib.md5(ip_address.encode()).hexdigest()
            locations = ["New York", "London", "Tokyo", "Sydney", "Berlin"]
            return locations[int(ip_hash[:2], 16) % len(locations)]

    def _calculate_time_risk(self, user_id: int) -> int:
        """Calculate risk based on time of access"""
        current_hour = datetime.utcnow().hour

        # Get user's typical login times (mock implementation)
        typical_hours = self._get_typical_login_hours(user_id)

        if current_hour not in typical_hours:
            return 15  # Unusual time

        return 0

    def _get_typical_login_hours(self, user_id: int) -> set:
        """Get user's typical login hours (mock)"""
        # In production, analyze historical login data
        # For demo, assume business hours
        return {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}

    def _calculate_failure_risk(self, user_id: int, ip_address: str) -> int:
        """Calculate risk based on recent failures"""
        # Check recent failed attempts for this user
        recent_failures = self.db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.event_type.in_(["login_failed", "mfa_failed"]),
            SecurityEvent.timestamp > datetime.utcnow() - timedelta(hours=24)
        ).count()

        return min(recent_failures * 5, 20)

    def _has_concurrent_sessions(self, user_id: int) -> bool:
        """Check if user has multiple active sessions"""
        active_sessions = self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).count()

        return active_sessions > 1
```

#### 5.2 Device Fingerprinting (2 hours)
```python
# src/auth/device_fingerprinting.py
import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime
import redis

class DeviceFingerprinting:
    def __init__(self, redis_client=None):
        self.redis = redis_client or redis.Redis.from_url("redis://localhost:6379")

    def generate_fingerprint(self, request_data: Dict[str, Any]) -> str:
        """Generate device fingerprint from request data"""
        fingerprint_data = {
            "user_agent": request_data.get("user_agent", ""),
            "accept_language": request_data.get("accept_language", ""),
            "accept_encoding": request_data.get("accept_encoding", ""),
            "screen_resolution": request_data.get("screen_resolution", ""),
            "timezone": request_data.get("timezone", ""),
            "platform": request_data.get("platform", ""),
            "plugins": sorted(request_data.get("plugins", [])),
            "fonts": sorted(request_data.get("fonts", [])),
            "canvas_fingerprint": request_data.get("canvas_fingerprint", ""),
        }

        # Create deterministic fingerprint
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]

    def store_device_info(self, user_id: int, fingerprint: str, device_info: Dict[str, Any]):
        """Store device information"""
        key = f"device:{user_id}:{fingerprint}"
        device_data = {
            "fingerprint": fingerprint,
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "device_info": device_info,
            "trust_score": 0
        }

        # Check if device exists
        existing_data = self.redis.get(key)
        if existing_data:
            existing_device = json.loads(existing_data)
            device_data["first_seen"] = existing_device["first_seen"]
            device_data["trust_score"] = min(existing_device.get("trust_score", 0) + 1, 10)

        self.redis.setex(key, 86400 * 90, json.dumps(device_data))  # 90 days

    def is_trusted_device(self, user_id: int, fingerprint: str) -> bool:
        """Check if device is trusted"""
        key = f"device:{user_id}:{fingerprint}"
        device_data = self.redis.get(key)

        if not device_data:
            return False

        device_info = json.loads(device_data)
        return device_info.get("trust_score", 0) >= 3

    def get_device_info(self, user_id: int, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get device information"""
        key = f"device:{user_id}:{fingerprint}"
        device_data = self.redis.get(key)

        if device_data:
            return json.loads(device_data)

        return None

# JavaScript for client-side fingerprinting
CLIENT_FINGERPRINT_JS = """
function collectDeviceFingerprint() {
    const fingerprint = {
        user_agent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screen_resolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        plugins: Array.from(navigator.plugins).map(p => p.name).sort(),
        canvas_fingerprint: getCanvasFingerprint()
    };

    return fingerprint;
}

function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprinting test 🔒', 2, 2);

    return canvas.toDataURL();
}

// Send fingerprint data with login request
document.getElementById('login-form').addEventListener('submit', function(e) {
    const fingerprintInput = document.createElement('input');
    fingerprintInput.type = 'hidden';
    fingerprintInput.name = 'device_fingerprint';
    fingerprintInput.value = JSON.stringify(collectDeviceFingerprint());

    this.appendChild(fingerprintInput);
});
"""
```

### Phase 6: Testing and Documentation (7 hours)

#### 6.1 Comprehensive Testing (4 hours)
```python
# tests/test_authentication.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.models.database import Base, User
from src.auth.authentication import AuthenticationService
from src.auth.password import PasswordValidator

@pytest.fixture
def db_session():
    # Create in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()

@pytest.fixture
def auth_service(db_session):
    return AuthenticationService(db_session)

class TestPasswordValidator:
    def test_valid_password(self):
        validator = PasswordValidator()
        is_valid, errors = validator.validate_password("SecureP@ssw0rd123!")
        assert is_valid
        assert len(errors) == 0

    def test_short_password(self):
        validator = PasswordValidator()
        is_valid, errors = validator.validate_password("Short1!")
        assert not is_valid
        assert "at least 12 characters" in str(errors)

    def test_missing_uppercase(self):
        validator = PasswordValidator()
        is_valid, errors = validator.validate_password("lowercase123!")
        assert not is_valid
        assert "uppercase letter" in str(errors)

    def test_common_password(self):
        validator = PasswordValidator()
        is_valid, errors = validator.validate_password("password123")
        assert not is_valid
        assert "too common" in str(errors)

class TestAuthenticationService:
    def test_register_user_success(self, auth_service):
        success, message = auth_service.register_user(
            "testuser",
            "test@example.com",
            "SecureP@ssw0rd123!"
        )
        assert success
        assert "successfully" in message

    def test_register_duplicate_username(self, auth_service):
        # Register first user
        auth_service.register_user("testuser", "test1@example.com", "SecureP@ssw0rd123!")

        # Try to register with same username
        success, message = auth_service.register_user(
            "testuser",
            "test2@example.com",
            "SecureP@ssw0rd123!"
        )
        assert not success
        assert "already exists" in message

    def test_authenticate_valid_credentials(self, auth_service):
        # Register user
        auth_service.register_user("testuser", "test@example.com", "SecureP@ssw0rd123!")

        # Authenticate
        success, user, message = auth_service.authenticate_password("testuser", "SecureP@ssw0rd123!", "127.0.0.1")
        assert success
        assert user is not None
        assert user.username == "testuser"

    def test_authenticate_invalid_password(self, auth_service):
        # Register user
        auth_service.register_user("testuser", "test@example.com", "SecureP@ssw0rd123!")

        # Try wrong password
        success, user, message = auth_service.authenticate_password("testuser", "wrongpassword", "127.0.0.1")
        assert not success
        assert user is None
        assert "Invalid credentials" in message

    def test_account_lockout(self, auth_service):
        # Register user
        auth_service.register_user("testuser", "test@example.com", "SecureP@ssw0rd123!")

        # Make 5 failed attempts
        for _ in range(5):
            auth_service.authenticate_password("testuser", "wrongpassword", "127.0.0.1")

        # Account should be locked
        success, user, message = auth_service.authenticate_password("testuser", "SecureP@ssw0rd123!", "127.0.0.1")
        assert not success
        assert "locked" in message

# tests/test_totp.py
import pytest
from src.auth.totp import TOTPService
from src.auth.mfa import MFAService

class TestTOTPService:
    def test_generate_secret(self):
        secret = TOTPService.generate_secret()
        assert len(secret) == 32
        assert secret.isalnum()

    def test_generate_qr_code(self):
        secret = TOTPService.generate_secret()
        qr_code = TOTPService.generate_qr_code(secret, "testuser")
        assert qr_code.startswith("data:image/png;base64,")

    def test_verify_totp(self):
        secret = TOTPService.generate_secret()

        # Get current token
        current_token = TOTPService.get_current_totp(secret)

        # Verify it
        assert TOTPService.verify_totp(secret, current_token)

        # Invalid token should fail
        assert not TOTPService.verify_totp(secret, "123456")

# tests/test_rate_limiting.py
import pytest
import redis
from src.auth.rate_limiter import RateLimiter

@pytest.fixture
def rate_limiter():
    # Use Redis database 15 for testing
    redis_client = redis.Redis(host='localhost', port=6379, db=15)
    redis_client.flushdb()  # Clear test database
    return RateLimiter(redis_client)

class TestRateLimiter:
    def test_within_rate_limit(self, rate_limiter):
        allowed, count, reset_time = rate_limiter.check_rate_limit("test_key", 5, 60)
        assert allowed
        assert count == 1

    def test_exceed_rate_limit(self, rate_limiter):
        # Make 5 requests (at limit)
        for i in range(5):
            allowed, count, reset_time = rate_limiter.check_rate_limit("test_key", 5, 60)
            assert allowed
            assert count == i + 1

        # 6th request should be denied
        allowed, count, reset_time = rate_limiter.check_rate_limit("test_key", 5, 60)
        assert not allowed
        assert count == 5

    def test_login_rate_limit(self, rate_limiter):
        # First attempt should succeed
        allowed, message = rate_limiter.check_login_rate_limit("192.168.1.1")
        assert allowed
        assert "1/10" in message

# tests/test_integration.py
import pytest
from fastapi.testclient import TestClient
from src.main import app  # Your FastAPI app

client = TestClient(app)

class TestCompleteAuthFlow:
    def test_complete_login_flow(self):
        # Register user
        response = client.post("/auth/register", json={
            "username": "integrationtest",
            "email": "integration@test.com",
            "password": "SecureP@ssw0rd123!"
        })
        assert response.status_code == 200

        # Login with password
        response = client.post("/auth/login", json={
            "username": "integrationtest",
            "password": "SecureP@ssw0rd123!"
        })
        assert response.status_code == 200
        data = response.json()

        if data.get("next_step") == "mfa":
            # Setup TOTP if MFA required
            user_id = data["user_id"]
            response = client.post(f"/auth/totp/setup/{user_id}")
            assert response.status_code == 200
        else:
            # Login completed
            assert "session_token" in data
```

#### 6.2 API Documentation (2 hours)
```python
# src/api/auth_endpoints.py
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from src.models.database import get_db
from src.auth.complete_mfa import CompleteMFAService
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/auth", tags=["Authentication"])

class UserRegistration(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str
    device_fingerprint: Optional[str] = None

class TOTPVerification(BaseModel):
    user_id: int
    token: str

class SMSVerification(BaseModel):
    user_id: int
    phone_number: str
    code: Optional[str] = None

@router.post("/register")
async def register_user(user_data: UserRegistration, db: Session = Depends(get_db)):
    """
    Register a new user account

    - **username**: Unique username (3-50 characters)
    - **email**: Valid email address
    - **password**: Strong password (min 12 chars, mixed case, numbers, symbols)

    Returns user ID and success message
    """
    mfa_service = CompleteMFAService(db)

    success, message = mfa_service.auth_service.register_user(
        user_data.username,
        user_data.email,
        user_data.password
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"success": True, "message": message}

@router.post("/login")
async def login_step1(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Initiate login process with username and password

    - **username**: Username or email
    - **password**: User's password
    - **device_fingerprint**: Optional device fingerprint for security

    Returns either complete login or MFA challenge
    """
    mfa_service = CompleteMFAService(db)
    ip_address = request.client.host

    result = mfa_service.initiate_login(
        login_data.username,
        login_data.password,
        ip_address
    )

    if not result["success"] and result.get("next_step") is None:
        raise HTTPException(status_code=401, detail=result["message"])

    return result

@router.post("/mfa/totp/verify")
async def verify_totp(totp_data: TOTPVerification, request: Request, db: Session = Depends(get_db)):
    """
    Verify TOTP token for MFA authentication

    - **user_id**: User ID from login step 1
    - **token**: 6-digit TOTP token from authenticator app

    Returns session token on success
    """
    mfa_service = CompleteMFAService(db)
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")

    result = mfa_service.verify_mfa_totp(
        totp_data.user_id,
        totp_data.token,
        ip_address,
        user_agent
    )

    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])

    return result

@router.post("/mfa/sms/send")
async def send_sms_code(sms_data: SMSVerification, db: Session = Depends(get_db)):
    """
    Send SMS verification code

    - **user_id**: User ID from login step 1
    - **phone_number**: Phone number to send code to

    Returns success message
    """
    mfa_service = CompleteMFAService(db)

    result = mfa_service.send_sms_verification(sms_data.user_id, sms_data.phone_number)

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])

    return result

@router.post("/mfa/sms/verify")
async def verify_sms_code(sms_data: SMSVerification, request: Request, db: Session = Depends(get_db)):
    """
    Verify SMS code for MFA authentication

    - **user_id**: User ID from login step 1
    - **phone_number**: Phone number code was sent to
    - **code**: 6-digit verification code from SMS

    Returns session token on success
    """
    if not sms_data.code:
        raise HTTPException(status_code=400, detail="Verification code required")

    mfa_service = CompleteMFAService(db)
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")

    result = mfa_service.verify_sms_code(
        sms_data.user_id,
        sms_data.phone_number,
        sms_data.code,
        ip_address,
        user_agent
    )

    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])

    return result
```

#### 6.3 Documentation Files (1 hour)
```markdown
# API.md
# MFA System API Reference

## Authentication Flow

### 1. User Registration
```http
POST /auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecureP@ssw0rd123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully"
}
```

### 2. Login Step 1 - Password Authentication
```http
POST /auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecureP@ssw0rd123!",
  "device_fingerprint": "a1b2c3d4e5f6..."
}
```

**Response (MFA Required):**
```json
{
  "success": true,
  "message": "Password verified. Choose MFA method.",
  "next_step": "mfa",
  "available_methods": ["totp", "sms", "email"],
  "user_id": 123
}
```

**Response (No MFA):**
```json
{
  "success": true,
  "message": "Login successful",
  "session_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "next_step": null,
  "user_id": 123
}
```

### 3. MFA Verification

#### TOTP Verification
```http
POST /auth/mfa/totp/verify
Content-Type: application/json

{
  "user_id": 123,
  "token": "123456"
}
```

#### SMS Verification
```http
POST /auth/mfa/sms/send
Content-Type: application/json

{
  "user_id": 123,
  "phone_number": "+1234567890"
}
```

```http
POST /auth/mfa/sms/verify
Content-Type: application/json

{
  "user_id": 123,
  "phone_number": "+1234567890",
  "code": "123456"
}
```

## Error Responses

All endpoints return errors in this format:
```json
{
  "detail": "Error message describing what went wrong"
}
```

Common HTTP status codes:
- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Authentication failed
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
```

## Common Issues and Solutions

### Issue 1: "TOTP token invalid"
**Problem**: Time synchronization issues between server and authenticator app.
**Solution**:
```python
# Increase TOTP window tolerance
settings.totp_window = 2  # Allow ±2 time steps (±60 seconds)
```

### Issue 2: SMS codes not being received
**Problem**: Mock SMS service is being used.
**Solution**: Check console output for SMS codes during development.
```python
# In production, replace with real SMS provider
def send_sms_code(self, phone_number: str, code: str):
    # Use Twilio, AWS SNS, or other SMS service
    pass
```

### Issue 3: High rate limit failures
**Problem**: Rate limiting is too strict for testing.
**Solution**: Adjust rate limits in settings for development.
```python
# Increase limits for development
MAX_LOGIN_ATTEMPTS = 20
LOCKOUT_DURATION_MINUTES = 5
```

### Issue 4: Database connection errors
**Problem**: PostgreSQL not running or misconfigured.
**Solution**:
```bash
# Start PostgreSQL and create database
createdb mfa_demo
export DATABASE_URL="postgresql://user:password@localhost/mfa_demo"
```

## Pro Tips

1. **Security Headers**: Always include security headers in production:
```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
```

2. **Backup Codes**: Always provide backup codes when TOTP is enabled.

3. **Session Security**: Use secure, httpOnly cookies for session tokens in production.

4. **Rate Limiting**: Implement different rate limits for different endpoints.

5. **Monitoring**: Log all security events for monitoring and analysis.