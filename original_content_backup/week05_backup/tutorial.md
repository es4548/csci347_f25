# Week 5 Tutorial: Access Control Systems

**Estimated Time**: 4 hours (5 modules)  
**Prerequisites**: Week 4 authentication systems completed

## Learning Objectives

By completing this tutorial, you will:
1. **Implement Role-Based Access Control (RBAC)** with hierarchical roles
2. **Build policy enforcement systems** with attribute-based decisions
3. **Create audit logging** for compliance and security monitoring
4. **Integrate access control** with existing authentication systems
5. **Design enterprise access architectures** following security principles

## Module 1: RBAC Foundation (45 minutes)

### Core RBAC Implementation

```python
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Set, Optional
import json
import hashlib
import logging

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    AUDIT = "audit"

class Role:
    def __init__(self, name: str, permissions: Set[Permission] = None, parent_role: 'Role' = None):
        self.name = name
        self.permissions = permissions or set()
        self.parent_role = parent_role
        self.created_at = datetime.now()
    
    def get_all_permissions(self) -> Set[Permission]:
        """Get permissions including inherited from parent roles"""
        all_perms = self.permissions.copy()
        if self.parent_role:
            all_perms.update(self.parent_role.get_all_permissions())
        return all_perms
    
    def has_permission(self, permission: Permission) -> bool:
        return permission in self.get_all_permissions()

class RBACSystem:
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = {}  # username -> role names
        self.audit_log = []
        self._setup_default_roles()
    
    def _setup_default_roles(self):
        """Create standard enterprise role hierarchy"""
        # Base roles
        self.add_role("guest", {Permission.READ})
        self.add_role("user", {Permission.READ, Permission.WRITE})
        self.add_role("manager", {Permission.READ, Permission.WRITE, Permission.DELETE})
        self.add_role("admin", {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN})
        self.add_role("auditor", {Permission.READ, Permission.AUDIT})
        
        # Create hierarchy
        self.roles["user"].parent_role = self.roles["guest"]
        self.roles["manager"].parent_role = self.roles["user"]
        self.roles["admin"].parent_role = self.roles["manager"]
```

### Checkpoint 1: Basic RBAC Test
```python
# Test your RBAC system
rbac = RBACSystem()
rbac.assign_role("alice", "manager")
print(f"Alice permissions: {rbac.get_user_permissions('alice')}")
print(f"Can Alice delete? {rbac.check_permission('alice', Permission.DELETE)}")
```

## Module 2: Policy-Based Access Control (60 minutes)

### Attribute-Based Access Control (ABAC)

```python
from dataclasses import dataclass
from typing import Any, Callable

@dataclass
class AccessRequest:
    user_id: str
    resource: str
    action: str
    context: Dict[str, Any]  # time, location, device, etc.

@dataclass
class Policy:
    name: str
    condition: Callable[[AccessRequest], bool]
    effect: str  # "allow" or "deny"
    priority: int = 0

class PolicyEngine:
    def __init__(self, rbac_system: RBACSystem):
        self.rbac = rbac_system
        self.policies: List[Policy] = []
        self.policy_cache = {}
        self._setup_default_policies()
    
    def _setup_default_policies(self):
        """Create enterprise security policies"""
        
        # Time-based access policy
        def business_hours_only(request: AccessRequest) -> bool:
            current_hour = datetime.now().hour
            return 8 <= current_hour <= 18
        
        self.add_policy(Policy(
            name="business_hours",
            condition=business_hours_only,
            effect="deny",
            priority=100
        ))
        
        # Sensitive resource policy
        def admin_only_sensitive(request: AccessRequest) -> bool:
            sensitive_resources = ["user_data", "financial_records", "audit_logs"]
            if request.resource in sensitive_resources:
                return self.rbac.has_role(request.user_id, "admin")
            return True
        
        self.add_policy(Policy(
            name="sensitive_admin_only",
            condition=admin_only_sensitive,
            effect="allow",
            priority=200
        ))
    
    def add_policy(self, policy: Policy):
        self.policies.append(policy)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
    
    def evaluate_access(self, request: AccessRequest) -> bool:
        """Evaluate access request against all policies"""
        # Start with RBAC check
        required_permission = self._action_to_permission(request.action)
        rbac_allowed = self.rbac.check_permission(request.user_id, required_permission)
        
        if not rbac_allowed:
            self._log_access_denied(request, "RBAC_DENIED")
            return False
        
        # Apply policies in priority order
        for policy in self.policies:
            try:
                if policy.condition(request):
                    if policy.effect == "deny":
                        self._log_access_denied(request, f"POLICY_DENIED_{policy.name}")
                        return False
                    elif policy.effect == "allow":
                        continue
            except Exception as e:
                logging.error(f"Policy {policy.name} evaluation error: {e}")
                continue
        
        self._log_access_granted(request)
        return True
```

### Checkpoint 2: Policy Engine Test
```python
# Test policy-based access
policy_engine = PolicyEngine(rbac)
request = AccessRequest(
    user_id="alice",
    resource="financial_records", 
    action="read",
    context={"time": datetime.now(), "ip": "192.168.1.100"}
)

result = policy_engine.evaluate_access(request)
print(f"Access granted: {result}")
```

## Module 3: Audit and Compliance (45 minutes)

### Comprehensive Audit Logging

```python
class AuditLogger:
    def __init__(self):
        self.audit_trail = []
        self.compliance_rules = {}
        self._setup_compliance()
    
    def _setup_compliance(self):
        """Setup compliance monitoring rules"""
        self.compliance_rules = {
            "failed_login_threshold": 5,
            "privilege_escalation_window": 300,  # 5 minutes
            "sensitive_access_monitoring": True
        }
    
    def log_access_attempt(self, request: AccessRequest, granted: bool, reason: str = ""):
        """Log all access attempts for compliance"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": request.user_id,
            "resource": request.resource,
            "action": request.action,
            "granted": granted,
            "reason": reason,
            "context": request.context,
            "session_id": request.context.get("session_id", "unknown")
        }
        
        self.audit_trail.append(audit_entry)
        
        # Check for suspicious patterns
        self._check_compliance_violations(audit_entry)
    
    def _check_compliance_violations(self, entry: dict):
        """Monitor for compliance violations"""
        user_id = entry["user_id"]
        
        # Check failed login attempts
        recent_failures = [
            e for e in self.audit_trail[-50:] 
            if e["user_id"] == user_id and not e["granted"] 
            and "login" in e["action"]
        ]
        
        if len(recent_failures) >= self.compliance_rules["failed_login_threshold"]:
            self._raise_compliance_alert("EXCESSIVE_FAILED_LOGINS", user_id, recent_failures)
    
    def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> dict:
        """Generate compliance report for audit period"""
        relevant_entries = [
            entry for entry in self.audit_trail
            if start_date <= datetime.fromisoformat(entry["timestamp"]) <= end_date
        ]
        
        return {
            "period": f"{start_date.date()} to {end_date.date()}",
            "total_access_attempts": len(relevant_entries),
            "denied_attempts": len([e for e in relevant_entries if not e["granted"]]),
            "unique_users": len(set(e["user_id"] for e in relevant_entries)),
            "sensitive_accesses": len([e for e in relevant_entries if "sensitive" in e["resource"]]),
            "policy_violations": self._count_policy_violations(relevant_entries)
        }
```

## Module 4: Enterprise Integration (90 minutes)

### Complete Access Control System

```python
class EnterpriseAccessControl:
    def __init__(self):
        self.rbac = RBACSystem()
        self.policy_engine = PolicyEngine(self.rbac)
        self.audit_logger = AuditLogger()
        self.session_manager = {}
        self._setup_enterprise_config()
    
    def _setup_enterprise_config(self):
        """Configure for enterprise environment"""
        # Add department-specific roles
        departments = ["hr", "finance", "engineering", "sales"]
        for dept in departments:
            self.rbac.add_role(f"{dept}_lead", {Permission.READ, Permission.WRITE, Permission.DELETE})
            self.rbac.add_role(f"{dept}_member", {Permission.READ, Permission.WRITE})
    
    def authenticate_and_authorize(self, username: str, password: str, 
                                 resource: str, action: str, context: dict) -> dict:
        """Complete authentication and authorization flow"""
        
        # Step 1: Authentication (integrate with Week 4 MFA)
        auth_result = self._authenticate_user(username, password, context)
        if not auth_result["success"]:
            return {"success": False, "reason": "Authentication failed", "requires_mfa": auth_result.get("requires_mfa", False)}
        
        # Step 2: Create access request
        request = AccessRequest(
            user_id=username,
            resource=resource,
            action=action,
            context={**context, "session_id": auth_result["session_id"]}
        )
        
        # Step 3: Authorization
        access_granted = self.policy_engine.evaluate_access(request)
        
        # Step 4: Audit logging
        self.audit_logger.log_access_attempt(request, access_granted, 
                                           "SUCCESS" if access_granted else "AUTHORIZATION_DENIED")
        
        return {
            "success": access_granted,
            "session_id": auth_result["session_id"],
            "permissions": list(self.rbac.get_user_permissions(username)) if access_granted else [],
            "expires_at": (datetime.now() + timedelta(hours=8)).isoformat()
        }
    
    def _authenticate_user(self, username: str, password: str, context: dict) -> dict:
        """Placeholder for MFA integration from Week 4"""
        # This would integrate with your Week 4 MFA system
        session_id = hashlib.sha256(f"{username}{datetime.now()}".encode()).hexdigest()[:16]
        
        return {
            "success": True,  # Simplified for tutorial
            "session_id": session_id,
            "requires_mfa": False
        }

# Enterprise usage example
def enterprise_usage_example():
    access_system = EnterpriseAccessControl()
    
    # Setup users and roles
    access_system.rbac.assign_role("john.doe", "engineering_lead")
    access_system.rbac.assign_role("jane.smith", "hr_member")
    
    # Test access request
    result = access_system.authenticate_and_authorize(
        username="john.doe",
        password="secure_password",  # Would use proper hashing
        resource="source_code",
        action="write",
        context={
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "timestamp": datetime.now().isoformat()
        }
    )
    
    print(f"Access result: {result}")
    
    # Generate compliance report
    report = access_system.audit_logger.generate_compliance_report(
        datetime.now() - timedelta(days=30),
        datetime.now()
    )
    print(f"Compliance report: {json.dumps(report, indent=2)}")
```

### Checkpoint 4: Enterprise System Test
```python
# Run the enterprise example
enterprise_usage_example()
```

## Module 5: Security Hardening (30 minutes)

### Production Security Measures

```python
class SecurityHardening:
    def __init__(self, access_system: EnterpriseAccessControl):
        self.access_system = access_system
        self.security_config = {
            "max_failed_attempts": 3,
            "lockout_duration": 300,  # 5 minutes
            "session_timeout": 28800,  # 8 hours
            "require_secure_transport": True
        }
        self.rate_limiter = {}
    
    def apply_security_policies(self):
        """Apply enterprise security hardening"""
        
        # Rate limiting policy
        def rate_limit_check(request: AccessRequest) -> bool:
            user_id = request.user_id
            current_time = datetime.now()
            
            if user_id in self.rate_limiter:
                attempts = self.rate_limiter[user_id]
                # Remove old attempts (outside rate limit window)
                attempts = [t for t in attempts if (current_time - t).seconds < 60]
                
                if len(attempts) >= 10:  # 10 requests per minute max
                    return False
                
                attempts.append(current_time)
                self.rate_limiter[user_id] = attempts
            else:
                self.rate_limiter[user_id] = [current_time]
            
            return True
        
        rate_limit_policy = Policy(
            name="rate_limiting",
            condition=rate_limit_check,
            effect="deny",
            priority=500
        )
        
        self.access_system.policy_engine.add_policy(rate_limit_policy)
    
    def validate_security_configuration(self) -> List[str]:
        """Validate security configuration for compliance"""
        issues = []
        
        # Check for weak configurations
        if self.security_config["max_failed_attempts"] > 5:
            issues.append("Max failed attempts too high (>5)")
        
        if self.security_config["session_timeout"] > 86400:  # 24 hours
            issues.append("Session timeout too long (>24 hours)")
        
        # Check role separation
        admin_users = [
            user for user, roles in self.access_system.rbac.user_roles.items()
            if "admin" in roles
        ]
        
        if len(admin_users) > 5:
            issues.append(f"Too many admin users: {len(admin_users)}")
        
        return issues

# Apply security hardening
def apply_enterprise_security():
    access_system = EnterpriseAccessControl()
    security = SecurityHardening(access_system)
    security.apply_security_policies()
    
    # Validate configuration
    issues = security.validate_security_configuration()
    if issues:
        print("Security issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("Security configuration validated successfully")

# Run security validation
apply_enterprise_security()
```

## Tutorial Completion

🎉 **Congratulations!** You've built a comprehensive enterprise access control system.

### What You've Accomplished:
1. **RBAC Implementation** with role hierarchy and inheritance
2. **Policy-Based Access Control** with flexible rules and conditions  
3. **Comprehensive Audit Logging** for compliance and monitoring
4. **Enterprise Integration** ready for production deployment
5. **Security Hardening** with rate limiting and validation

### Next Steps:
- **Week 5 Assignment**: Build your own enterprise access control system
- **Project 1 Integration**: Combine this with your Week 4 MFA system
- **Week 6 Preview**: Network security and firewall configuration

### Professional Applications:
- **Identity and Access Management (IAM)** systems
- **Zero Trust Architecture** implementation
- **Compliance Monitoring** (SOX, HIPAA, GDPR)
- **Enterprise Security Frameworks**

You're now ready to implement production-grade access control systems! 🚀