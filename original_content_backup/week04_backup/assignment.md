# Week 4 Assignment: Multi-Factor Authentication Foundation System

**Due**: End of Week 4 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Submit Pull Request URL to Canvas  
**🚀 PROJECT 1 PREPARATION**: This assignment builds essential components for Project 1 - Enterprise MFA System (100 points)

## 🎯 Assignment Overview

Build a foundational multi-factor authentication (MFA) system that serves as the core engine for Project 1's enterprise-grade solution. This assignment focuses on implementing essential MFA components with proper security controls, providing the technical foundation you'll extend into a full enterprise system.

### 🚀 Project 1 Connection
This assignment is strategically designed to prepare you for **Project 1: Enterprise MFA System** (100 points, due Week 5). You'll build:
- **Core authentication engine** that Project 1 will extend
- **Security framework** that meets enterprise requirements
- **Database architecture** that scales to administrative features  
- **Risk assessment foundation** for adaptive authentication

**Success Strategy**: Treat this assignment as Project 1's foundation. High-quality work here significantly reduces Project 1 complexity.

## 📋 Requirements

### Core Functionality (15 points)

Your MFA system must implement these features:

#### 1. Multi-Factor Authentication Engine (25 points)
- **TOTP (Time-based One-Time Password)** implementation using HMAC-SHA1
- **Backup authentication codes** generation and validation
- **QR code generation** for authenticator app setup
- **Rate limiting** to prevent brute force attacks

#### 2. Secure Session Management (25 points)
- **JWT token generation** with proper claims and expiration
- **Session validation** and renewal mechanisms
- **Secure logout** with token invalidation
- **Session hijacking protection** with IP and user agent validation

#### 3. Risk-Based Authentication (20 points)
- **Device fingerprinting** based on user agent and screen resolution
- **Location-based risk assessment** using IP geolocation
- **Suspicious activity detection** (unusual login times, failed attempts)
- **Adaptive authentication** requiring additional factors for high-risk scenarios

### Web Interface (5 points)

Create a Flask-based web application with these pages:

```
/register          - User registration with MFA setup
/login             - Primary authentication (username/password)
/mfa-setup         - TOTP setup with QR code display
/mfa-verify        - Second factor verification
/dashboard         - Protected area requiring authentication
/profile           - User profile with authentication history
/logout            - Secure session termination
```

### Security Features (5 points)

- **Password hashing** with bcrypt and appropriate cost factor
- **CSRF protection** for all forms
- **Input validation** and sanitization
- **Secure random number generation** for tokens and codes

## 🔧 Technical Specifications

### Required Libraries
```python
from flask import Flask, request, render_template, redirect, session, jsonify
from flask_session import Session
import pyotp
import qrcode
import jwt
import bcrypt
import secrets
import datetime
import requests
import sqlite3
import json
```

### File Structure
```
mfa_system.py             # Main Flask application
auth_manager.py           # Authentication logic
risk_engine.py            # Risk assessment functionality
database.py               # Database operations
templates/                # HTML templates
  ├── login.html
  ├── mfa_setup.html
  ├── mfa_verify.html
  ├── dashboard.html
  └── profile.html
static/                   # CSS and JavaScript files
users.db                  # SQLite database
README.txt                # Implementation documentation
```

### Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    backup_codes TEXT,  -- JSON array of backup codes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Authentication logs
CREATE TABLE auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT,  -- 'login_success', 'login_failure', 'mfa_success', etc.
    ip_address TEXT,
    user_agent TEXT,
    risk_score REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 📝 Detailed Requirements

### 1. Authentication Manager (Project 1 Foundation Component)
```python
class AuthManager:
    def __init__(self, db_connection):
        self.db = db_connection
        
    def register_user(self, username, email, password):
        """
        Register new user with secure password hashing
        
        Args:
            username (str): Unique username
            email (str): User's email address
            password (str): Plain text password
            
        Returns:
            dict: Registration result with user ID or error
        """
        # Hash password with bcrypt
        # Generate TOTP secret
        # Create backup codes
        # Store in database
        
    def authenticate_user(self, username, password, ip_address, user_agent):
        """
        Primary authentication with username/password
        
        Args:
            username (str): Username
            password (str): Password
            ip_address (str): Client IP address
            user_agent (str): Client user agent
            
        Returns:
            dict: Authentication result with user info or error
        """
        # Verify username and password
        # Check account lockout status
        # Log authentication attempt
        # Return user data if successful
        
    def verify_totp(self, user_id, token):
        """
        Verify TOTP token for second factor
        
        Args:
            user_id (int): User identifier
            token (str): 6-digit TOTP code
            
        Returns:
            bool: True if token is valid
        """
        # Get user's TOTP secret
        # Verify token with time window tolerance
        # Prevent token replay attacks
        
    def create_session(self, user_id, ip_address, user_agent):
        """
        Create secure session with JWT token
        
        Args:
            user_id (int): User identifier
            ip_address (str): Client IP
            user_agent (str): Client user agent
            
        Returns:
            str: JWT session token
        """
        # Generate session ID
        # Create JWT with proper claims
        # Store session in database
        # Return token
```

### 2. Risk Assessment Engine (Project 1 Foundation Component)
```python
class RiskEngine:
    def __init__(self, db_connection):
        self.db = db_connection
        
    def assess_login_risk(self, user_id, ip_address, user_agent, timestamp):
        """
        Assess risk level for login attempt
        
        Args:
            user_id (int): User attempting login
            ip_address (str): Client IP address
            user_agent (str): Client user agent
            timestamp (datetime): Login timestamp
            
        Returns:
            dict: Risk assessment with score and factors
        """
        risk_score = 0.0
        risk_factors = []
        
        # Check for new device (user agent analysis)
        # Assess geographic location (IP geolocation)
        # Analyze time patterns (unusual login hours)
        # Check recent failed attempts
        # Calculate composite risk score
        
        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'factors': risk_factors
        }
        
    def _get_risk_level(self, score):
        """Convert numerical score to risk level"""
        if score < 0.3:
            return 'LOW'
        elif score < 0.7:
            return 'MEDIUM'
        else:
            return 'HIGH'
```

### 3. Web Application Routes (Project 1 Foundation Component)
```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Primary authentication
        auth_result = auth_manager.authenticate_user(
            username, password, ip_address, user_agent
        )
        
        if auth_result['success']:
            # Assess login risk
            risk_assessment = risk_engine.assess_login_risk(
                auth_result['user_id'], ip_address, user_agent, datetime.now()
            )
            
            # Store in session for MFA step
            session['pending_user_id'] = auth_result['user_id']
            session['risk_level'] = risk_assessment['risk_level']
            
            return redirect('/mfa-verify')
        else:
            return render_template('login.html', error=auth_result['error'])
    
    return render_template('login.html')

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pending_user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        token = request.form['token']
        user_id = session['pending_user_id']
        
        # Verify TOTP token
        if auth_manager.verify_totp(user_id, token):
            # Create secure session
            session_token = auth_manager.create_session(
                user_id, request.remote_addr, request.headers.get('User-Agent')
            )
            
            # Store in secure session
            session['token'] = session_token
            session['user_id'] = user_id
            session.pop('pending_user_id')
            
            return redirect('/dashboard')
        else:
            return render_template('mfa_verify.html', error='Invalid code')
    
    return render_template('mfa_verify.html')
```

## 💻 Example Usage

```bash
# Start the MFA system
python mfa_system.py

# Navigate to http://localhost:5000
# Register a new account
# Set up TOTP authentication with QR code
# Test login flow with various risk scenarios
```

### Example Authentication Flow
1. **User Registration**: Create account with secure password
2. **MFA Setup**: Scan QR code with authenticator app (Google Authenticator, Authy)
3. **Login Attempt**: Enter username/password
4. **Risk Assessment**: System evaluates login risk factors
5. **MFA Challenge**: Enter TOTP code from authenticator app
6. **Session Creation**: Generate secure JWT session token
7. **Access Dashboard**: Navigate to protected resources

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|----------|
| **MFA Implementation** | 60% | 15 points |
| **Web Interface** | 20% | 5 points |
| **Security Practices** | 20% | 5 points |

### 5-Point Scale Criteria

**TOTP Implementation (15 points)**
- **Excellent (15)**: Perfect TOTP implementation, QR codes, backup codes, proper time windows, rate limiting
- **Proficient (12)**: Good TOTP functionality with most security features working
- **Developing (9)**: Basic TOTP works, some security features missing
- **Needs Improvement (6)**: TOTP partially functional, significant gaps
- **Inadequate (3)**: TOTP doesn't work properly or major security flaws
- **No Submission (0)**: Missing or no attempt

**Web Interface (5 points)**
- **Excellent (5)**: All pages functional, good UX, proper error handling
- **Proficient (4)**: Most pages work well, adequate interface
- **Developing (3)**: Basic pages functional, some issues
- **Needs Improvement (2)**: Some functionality broken
- **Inadequate (1)**: Major interface problems
- **No Submission (0)**: Missing or no attempt

**Security Practices (5 points)**
- **Excellent (5)**: Proper TOTP security, rate limiting, replay protection, input validation
- **Proficient (4)**: Good TOTP security practices, minor vulnerabilities
- **Developing (3)**: Basic TOTP security considerations
- **Needs Improvement (2)**: Limited TOTP security practices
- **Inadequate (1)**: Poor TOTP security implementation
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **23-25 points (A)**: Excellent TOTP implementation with strong security
- **20-22 points (B)**: Good TOTP implementation with minor issues
- **18-19 points (C)**: Satisfactory TOTP functionality
- **15-17 points (D)**: Basic TOTP functionality, security concerns
- **Below 15 points (F)**: Inadequate TOTP implementation

## 🚀 Optional Challenge

**Advanced TOTP Features**: Implement TOTP with different time periods (15, 30, 60 seconds), support for 6 and 8-digit codes, and tolerance for clock drift. Document the security trade-offs of each configuration.

## 📋 Submission Checklist

Before submitting, verify:

**Core TOTP Functionality:**
- [ ] **TOTP setup and QR code generation work correctly**
- [ ] **TOTP authentication functions properly with authenticator apps**
- [ ] **Backup codes generation and validation work**
- [ ] **Rate limiting prevents brute force attacks**
- [ ] **Web interface allows TOTP setup and verification**
- [ ] **Token validation handles time windows correctly**
- [ ] **Security measures protect against replay attacks**
- [ ] **Code is well-structured and documented**
- [ ] **README.txt explains TOTP implementation**

### Testing Your MFA System
```bash
# Test complete authentication flow
1. Register new user account
2. Set up TOTP with QR code scanning
3. Log out and attempt login
4. Test TOTP verification
5. Verify dashboard access

# Test risk scenarios
1. Login from different IP addresses
2. Use different browsers/devices
3. Attempt login at unusual times
4. Test with incorrect TOTP codes

# Test security features
1. Verify password hashing strength
2. Test session timeout behavior
3. Confirm CSRF protection works
4. Validate input sanitization
```

## 📚 Resources and References

### Assignment-Specific Resources

### Documentation
- **PyOTP Documentation**: https://pypi.org/project/pyotp/
- **JWT Specification**: https://tools.ietf.org/html/rfc7519
- **TOTP Algorithm**: https://tools.ietf.org/html/rfc6238

### Security Standards
- **NIST SP 800-63B Authentication**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

### Example Implementation Structure
```python
# mfa_system.py - Main application
from flask import Flask, render_template, request, session, redirect
from auth_manager import AuthManager
from risk_engine import RiskEngine
from database import DatabaseManager

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Initialize components
db_manager = DatabaseManager('users.db')
auth_manager = AuthManager(db_manager.get_connection())
risk_engine = RiskEngine(db_manager.get_connection())

@app.route('/')
def index():
    return redirect('/login')

# Define all routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration logic
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Primary authentication
    pass

@app.route('/mfa-setup', methods=['GET', 'POST'])
def mfa_setup():
    # TOTP setup with QR code
    pass

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    # Second factor verification
    pass

@app.route('/dashboard')
def dashboard():
    # Protected area
    pass

if __name__ == '__main__':
    db_manager.init_database()
    app.run(debug=True, port=5000)
```

## 🚀 Project 1 Transition Strategy

### From Assignment to Enterprise System

**Week 4 Assignment → Week 5 Project 1**:
1. **Authentication Core**: Your assignment's MFA engine becomes Project 1's foundation
2. **Database Expansion**: Add administrative tables, audit logs, compliance features
3. **Interface Enhancement**: Transform basic web interface into admin dashboard
4. **Security Scaling**: Extend risk assessment to enterprise compliance requirements
5. **Integration Features**: Add SSO, LDAP, and enterprise directory support

### Recommended Project 1 Timeline
- **Week 4 Weekend**: Begin Project 1 architecture using assignment foundation
- **Week 5 Early**: Focus on administrative interface and enterprise features
- **Week 5 Mid**: Advanced authentication factors and compliance reporting
- **Week 5 Late**: Documentation, testing, and presentation preparation

### Success Tips
- **Modular Design**: Structure assignment code for easy Project 1 extension
- **Enterprise Thinking**: Consider multi-tenant, audit, and administrative requirements
- **Documentation**: Document design decisions for Project 1 expansion
- **Testing**: Build comprehensive test suite that extends to Project 1

## ❓ Frequently Asked Questions

**Q: Which authenticator apps should I test with?**  
A: Google Authenticator, Authy, and Microsoft Authenticator are good choices for testing TOTP compatibility.

**Q: How should I handle backup codes?**  
A: Generate 10-12 single-use backup codes, hash them before storage, and invalidate after use.

**Q: What constitutes a high-risk login?**  
A: New device, unusual location, off-hours access, recent failed attempts, or multiple risk factors combined.

**Q: How long should sessions last?**  
A: Consider 30 minutes for high-security applications, 24 hours for standard applications, with sliding expiration.

**Q: Should I implement remember device functionality?**  
A: This is bonus material - implement device tokens that reduce MFA requirements for trusted devices.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

**Assignment Quality:**
1. **Would I trust this MFA system to protect my own sensitive accounts?**
2. **Does the risk assessment meaningfully improve security?**
3. **Are sessions properly secured against hijacking?**
4. **Have I tested the TOTP implementation with real authenticator apps?**
5. **Does the system gracefully handle all error conditions?**

**Project 1 Readiness:**
6. **Can I easily extend this code for enterprise administrative features?**
7. **Is my database schema ready for audit logs and user management?**
8. **Would my authentication engine support additional factors and integrations?**
9. **Is my code documented well enough to build upon for Project 1?**
10. **Have I identified specific areas to enhance for the enterprise system?**

---

**Need Help?**
- Review the authentication tutorial materials
- Test your TOTP implementation with multiple authenticator apps
- Check Canvas discussions for common integration issues
- Attend office hours for security design review and Project 1 planning
- Consider this assignment's architecture for Project 1 scalability

**Success Path!** This assignment provides the foundation for Project 1's enterprise-grade authentication system. Focus on building modular, extensible code that you'll enhance rather than replace.

## 🎯 Assignment Success = Project 1 Head Start

**High-quality work on this assignment will:**
- ✅ **Reduce Project 1 complexity** by providing tested core components
- ✅ **Accelerate development** with proven authentication architecture
- ✅ **Improve Project 1 grades** through solid foundational implementation
- ✅ **Enable advanced features** by handling basics correctly from the start

**Project 1 Preview**: Next week you'll transform this foundation into a comprehensive enterprise system with administrative dashboards, compliance reporting, advanced user management, and integration capabilities.