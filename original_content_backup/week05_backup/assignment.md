# Week 5 Assignment: Enterprise Access Control System

**Due**: End of Week 5 (see Canvas for exact deadline)  
**Points**: 25 | **Estimated Time**: 4 hours  
**Prerequisites**: Week 5 tutorial completed, Week 4 MFA system knowledge

---

## 🎯 **Assignment Overview**

Build a comprehensive enterprise access control system that integrates with authentication mechanisms and provides role-based authorization with policy enforcement. This assignment prepares you for completing **Project 1: Enterprise MFA System** (due this week).

---

## 📋 **Requirements**

### **Core Functionality (15 points)**

1. **Role-Based Access Control (5 points)**
   - Implement hierarchical role system (guest → user → manager → admin)
   - Support role inheritance and permission aggregation
   - Department-specific roles (engineering_lead, hr_member, etc.)

2. **Policy Engine (5 points)**
   - Time-based access policies (business hours enforcement)
   - Resource-based policies (sensitive data protection)
   - Context-aware authorization (IP address, device type)

3. **Audit and Compliance (5 points)**
   - Comprehensive access logging with timestamps
   - Compliance report generation
   - Violation detection and alerting

### **Professional Features (7 points)**

4. **Enterprise Integration (4 points)**
   - Session management integration
   - Multi-department user organization
   - Rate limiting and security hardening
   - Configuration validation

5. **Error Handling and Security (3 points)**
   - Graceful handling of authentication failures
   - Protection against privilege escalation
   - Secure session token generation
   - Input validation and sanitization

### **Documentation and Testing (3 points)**

6. **Professional Documentation**
   - Clear README with usage instructions
   - API documentation for all classes and methods
   - Security configuration guidelines

7. **Comprehensive Testing**
   - Unit tests for core functionality
   - Integration tests for policy enforcement
   - Edge case testing (failed authentications, expired sessions)

---

## 🛠️ **Deliverables**

Create a complete Python package with the following structure:

```
access_control_system/
├── README.md                 # Complete documentation
├── requirements.txt          # Python dependencies  
├── access_control.py         # Main implementation
├── policies.py              # Policy definitions
├── audit.py                 # Audit and compliance
├── test_access_control.py   # Test suite
└── example_usage.py         # Demonstration script
```

### **Required Classes**

Your implementation must include:

```python
class AccessControlSystem:
    """Main enterprise access control system"""
    
    def authenticate_user(self, username: str, password: str, context: dict) -> dict:
        """Authenticate user with context awareness"""
        pass
    
    def authorize_request(self, user_id: str, resource: str, action: str, context: dict) -> bool:
        """Authorize access request with policy evaluation"""
        pass
    
    def assign_role(self, user_id: str, role_name: str) -> bool:
        """Assign role to user with validation"""
        pass
    
    def revoke_access(self, user_id: str, resource: str = None) -> bool:
        """Revoke user access with audit trail"""
        pass

class PolicyEngine:
    """Enterprise policy enforcement engine"""
    
    def add_policy(self, policy: 'Policy') -> None:
        """Add new policy with priority ordering"""
        pass
    
    def evaluate_policies(self, request: 'AccessRequest') -> bool:
        """Evaluate all applicable policies"""
        pass

class AuditLogger:
    """Comprehensive audit and compliance logging"""
    
    def log_access_attempt(self, request: 'AccessRequest', result: bool) -> None:
        """Log access attempt with full context"""
        pass
    
    def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> dict:
        """Generate detailed compliance report"""
        pass
```

---

## 🧪 **Testing Requirements**

Your test suite must validate:

1. **RBAC Functionality**
   ```python
   def test_role_hierarchy():
       """Test role inheritance and permission aggregation"""
       pass
   
   def test_permission_checking():
       """Test permission validation for different roles"""
       pass
   ```

2. **Policy Enforcement**
   ```python
   def test_time_based_policies():
       """Test business hours enforcement"""
       pass
   
   def test_resource_protection():
       """Test sensitive resource access policies"""
       pass
   ```

3. **Integration Testing**
   ```python
   def test_full_authorization_flow():
       """Test complete authentication and authorization"""
       pass
   
   def test_audit_logging():
       """Test comprehensive audit trail generation"""
       pass
   ```

---

## 📊 **Grading Rubric**

| Component | Excellent (5) | Good (4) | Satisfactory (3) | Needs Work (2) | Incomplete (1) |
|-----------|---------------|----------|------------------|----------------|----------------|
| **RBAC Implementation** | Hierarchical roles with inheritance, department organization | Basic roles with some hierarchy | Simple role assignment | Limited role functionality | Minimal implementation |
| **Policy Engine** | Context-aware policies, priority handling, flexible rules | Time and resource policies work | Basic policy enforcement | Simple policy checking | Limited policy support |
| **Audit & Compliance** | Comprehensive logging, violation detection, detailed reports | Good logging with basic reports | Basic audit trail | Simple logging | Minimal audit support |
| **Enterprise Features** | Session management, rate limiting, security hardening | Integration features work well | Basic enterprise features | Some integration attempts | Limited enterprise focus |
| **Documentation & Tests** | Complete docs, comprehensive tests, professional quality | Good documentation and tests | Basic docs and testing | Limited documentation | Minimal docs/tests |

---

## 🔗 **Project 1 Integration**

**Important**: This assignment directly supports your **Project 1: Enterprise MFA System** (100 points, due end of Week 5).

### **How to Integrate**:
1. **Use your Week 4 MFA system** for the authentication component
2. **Extend with this access control system** for authorization
3. **Combine audit trails** for comprehensive security monitoring
4. **Apply enterprise hardening** for production readiness

### **Project 1 Preparation Checklist**:
- [ ] MFA authentication working (from Week 4)
- [ ] RBAC authorization implemented (this assignment)
- [ ] Session management integrated
- [ ] Audit logging comprehensive
- [ ] Security hardening applied
- [ ] Documentation complete

---

## 💡 **Implementation Hints**

### **Starting Point**
```python
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib

class AccessControlSystem:
    def __init__(self):
        self.rbac_system = RBACSystem()
        self.policy_engine = PolicyEngine(self.rbac_system)
        self.audit_logger = AuditLogger()
        self.session_store = {}
    
    def process_access_request(self, username: str, resource: str, 
                              action: str, context: dict) -> dict:
        """Complete access control workflow"""
        # 1. Authenticate (integrate Week 4 MFA)
        # 2. Authorize with policies
        # 3. Log attempt
        # 4. Return result with session info
        pass
```

### **Key Security Considerations**
- **Session Security**: Use cryptographically secure session tokens
- **Rate Limiting**: Prevent brute force attacks
- **Input Validation**: Sanitize all user inputs
- **Audit Trail**: Log all access attempts, not just failures
- **Least Privilege**: Default to deny, explicit allow

---

## 📤 **Submission Instructions**

1. **Create GitHub Repository**
   ```bash
   git init access-control-system
   cd access-control-system
   # Add your implementation files
   git add .
   git commit -m "Week 5: Enterprise Access Control System"
   git push origin main
   ```

2. **Submit Pull Request**
   - Base: `course-main` branch
   - Compare: your implementation branch
   - Title: `Week 5 Assignment: [Your Name] - Access Control System`
   - Description: Include key features, challenges overcome, and Project 1 integration plan

3. **Include in PR Description**:
   - **Demo Instructions**: How to run your system
   - **Test Results**: Summary of test coverage and results
   - **Security Features**: Key security measures implemented
   - **Project 1 Integration**: How this supports your major project

---

## 🎯 **Success Criteria**

**Minimum Success** (C-level):
- [ ] Basic RBAC with role assignment works
- [ ] Simple policy enforcement functional
- [ ] Basic audit logging present
- [ ] Core functionality tested

**Target Success** (B-level):
- [ ] Hierarchical roles with inheritance
- [ ] Context-aware policy enforcement
- [ ] Comprehensive audit trails
- [ ] Good integration capabilities

**Excellence** (A-level):
- [ ] Enterprise-grade security features
- [ ] Production-ready hardening
- [ ] Comprehensive documentation and testing
- [ ] Clear Project 1 integration path
- [ ] Professional code quality and architecture

---

## 🆘 **Getting Help**

**Stuck on implementation?**
1. Review Week 5 tutorial code examples
2. Check Week 4 MFA system for authentication patterns
3. Post specific questions in Canvas discussions
4. Use office hours for architecture guidance

**Testing challenges?**
1. Start with simple unit tests
2. Build up to integration scenarios
3. Focus on edge cases (expired sessions, invalid roles)
4. Test policy combinations thoroughly

**Project 1 integration questions?**
1. Plan your architecture before coding
2. Consider how components will work together
3. Think about data flow and error handling
4. Start early - Project 1 is due this week!

---

## 🔜 **Next Week Preview**

**Week 6: Network Security** will build on your access control foundation by adding:
- Network-level access controls (firewalls)
- Network segmentation strategies
- Intrusion detection and prevention
- Integration with identity and access management

Your solid access control implementation will be valuable as we move to network-wide security architecture!

---

*💡 **Pro Tip**: This assignment is excellent preparation for IAM (Identity and Access Management) interviews. The concepts of RBAC, policy engines, and audit logging are fundamental to enterprise security roles.*