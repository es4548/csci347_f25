# Week 5 Homework Hints: Role-Based Access Control System

## 🎯 Quick Start Guide (4 hours total)

### Time Breakdown
- **RBAC Model Design**: 1 hour
- **Core RBAC Implementation**: 2 hours
- **File System Demo**: 1 hour

## 📋 Step-by-Step Implementation

### Step 1: Understanding RBAC Concepts (30 minutes)

**Key RBAC Components:**
- **Users**: People who need access
- **Roles**: Job functions (admin, user, guest)
- **Permissions**: Specific actions (read, write, execute)
- **Resources**: Things being protected (files, databases, etc.)

**RBAC Principle**: Users → Roles → Permissions → Resources

**Example Hierarchy:**
```
admin    → can do everything
user     → can read/write own files
guest    → can only read public files
```

### Step 2: Environment Setup (15 minutes)

```bash
mkdir week05-rbac
cd week05-rbac
mkdir files audit_logs

touch rbac_system.py
touch file_system_demo.py
```

### Step 3: Core RBAC Model (60 minutes)

```python
from enum import Enum
from datetime import datetime
import json
import os
from typing import Dict, List, Set, Optional

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"

class User:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email
        self.roles: Set[str] = set()
        self.created_at = datetime.now()

    def add_role(self, role: str):
        self.roles.add(role)

    def remove_role(self, role: str):
        self.roles.discard(role)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def to_dict(self):
        return {
            "username": self.username,
            "email": self.email,
            "roles": list(self.roles),
            "created_at": self.created_at.isoformat()
        }

class Role:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.permissions: Set[Permission] = set()
        self.inherits_from: Set[str] = set()  # Role inheritance

    def add_permission(self, permission: Permission):
        self.permissions.add(permission)

    def remove_permission(self, permission: Permission):
        self.permissions.discard(permission)

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def inherit_from(self, role_name: str):
        self.inherits_from.add(role_name)

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "permissions": [p.value for p in self.permissions],
            "inherits_from": list(self.inherits_from)
        }

class Resource:
    def __init__(self, name: str, owner: str, resource_type: str = "file"):
        self.name = name
        self.owner = owner
        self.resource_type = resource_type
        self.created_at = datetime.now()
        # Resource-specific permissions (ACL-style)
        self.acl: Dict[str, Set[Permission]] = {}

    def grant_permission(self, user_or_role: str, permission: Permission):
        if user_or_role not in self.acl:
            self.acl[user_or_role] = set()
        self.acl[user_or_role].add(permission)

    def revoke_permission(self, user_or_role: str, permission: Permission):
        if user_or_role in self.acl:
            self.acl[user_or_role].discard(permission)

    def to_dict(self):
        return {
            "name": self.name,
            "owner": self.owner,
            "resource_type": self.resource_type,
            "created_at": self.created_at.isoformat(),
            "acl": {k: [p.value for p in v] for k, v in self.acl.items()}
        }
```

### Step 4: RBAC Manager (75 minutes)

```python
class RBACManager:
    def __init__(self, data_file: str = "rbac_data.json"):
        self.data_file = data_file
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, Role] = {}
        self.resources: Dict[str, Resource] = {}
        self.audit_log: List[Dict] = []

        # Initialize default roles
        self._setup_default_roles()
        self.load_data()

    def _setup_default_roles(self):
        """Create default role hierarchy"""
        # Guest role - minimal permissions
        guest = Role("guest", "Basic read-only access")
        guest.add_permission(Permission.READ)

        # User role - standard user permissions
        user = Role("user", "Standard user access")
        user.add_permission(Permission.READ)
        user.add_permission(Permission.WRITE)
        user.inherit_from("guest")

        # Admin role - full permissions
        admin = Role("admin", "Administrative access")
        admin.add_permission(Permission.READ)
        admin.add_permission(Permission.WRITE)
        admin.add_permission(Permission.EXECUTE)
        admin.add_permission(Permission.DELETE)
        admin.add_permission(Permission.ADMIN)
        admin.inherit_from("user")

        self.roles = {
            "guest": guest,
            "user": user,
            "admin": admin
        }

    def create_user(self, username: str, email: str, initial_role: str = "guest") -> bool:
        """Create a new user"""
        if username in self.users:
            self.log_action("create_user", username, "FAILED", "User already exists")
            return False

        user = User(username, email)
        if initial_role in self.roles:
            user.add_role(initial_role)

        self.users[username] = user
        self.log_action("create_user", username, "SUCCESS", f"User created with role {initial_role}")
        self.save_data()
        return True

    def assign_role(self, username: str, role_name: str, assigned_by: str) -> bool:
        """Assign role to user"""
        if username not in self.users:
            self.log_action("assign_role", assigned_by, "FAILED", f"User {username} not found")
            return False

        if role_name not in self.roles:
            self.log_action("assign_role", assigned_by, "FAILED", f"Role {role_name} not found")
            return False

        self.users[username].add_role(role_name)
        self.log_action("assign_role", assigned_by, "SUCCESS",
                       f"Assigned role {role_name} to {username}")
        self.save_data()
        return True

    def check_permission(self, username: str, resource_name: str, permission: Permission) -> bool:
        """Check if user has permission for resource"""
        if username not in self.users:
            self.log_action("check_permission", username, "FAILED", "User not found")
            return False

        user = self.users[username]

        # Check if resource exists
        if resource_name in self.resources:
            resource = self.resources[resource_name]

            # Resource owner always has full access
            if resource.owner == username:
                self.log_action("check_permission", username, "SUCCESS",
                               f"Owner access to {resource_name}")
                return True

            # Check resource-specific ACL
            for role_or_user in [username] + list(user.roles):
                if role_or_user in resource.acl and permission in resource.acl[role_or_user]:
                    self.log_action("check_permission", username, "SUCCESS",
                                   f"ACL access to {resource_name}")
                    return True

        # Check role-based permissions
        effective_permissions = self.get_effective_permissions(username)
        has_permission = permission in effective_permissions

        status = "SUCCESS" if has_permission else "DENIED"
        self.log_action("check_permission", username, status,
                       f"Permission {permission.value} for {resource_name}")

        return has_permission

    def get_effective_permissions(self, username: str) -> Set[Permission]:
        """Get all effective permissions for a user"""
        if username not in self.users:
            return set()

        permissions = set()
        user = self.users[username]

        # Collect permissions from all roles (including inherited)
        for role_name in user.roles:
            permissions.update(self._get_role_permissions(role_name))

        return permissions

    def _get_role_permissions(self, role_name: str) -> Set[Permission]:
        """Get all permissions for a role (including inherited)"""
        if role_name not in self.roles:
            return set()

        role = self.roles[role_name]
        permissions = role.permissions.copy()

        # Add inherited permissions
        for inherited_role in role.inherits_from:
            permissions.update(self._get_role_permissions(inherited_role))

        return permissions

    def create_resource(self, name: str, owner: str, resource_type: str = "file") -> bool:
        """Create a new resource"""
        if name in self.resources:
            self.log_action("create_resource", owner, "FAILED", f"Resource {name} already exists")
            return False

        resource = Resource(name, owner, resource_type)
        self.resources[name] = resource
        self.log_action("create_resource", owner, "SUCCESS", f"Created resource {name}")
        self.save_data()
        return True

    def grant_resource_permission(self, resource_name: str, user_or_role: str,
                                 permission: Permission, granted_by: str) -> bool:
        """Grant permission on specific resource"""
        if resource_name not in self.resources:
            self.log_action("grant_permission", granted_by, "FAILED",
                           f"Resource {resource_name} not found")
            return False

        resource = self.resources[resource_name]
        resource.grant_permission(user_or_role, permission)

        self.log_action("grant_permission", granted_by, "SUCCESS",
                       f"Granted {permission.value} on {resource_name} to {user_or_role}")
        self.save_data()
        return True

    def log_action(self, action: str, user: str, status: str, details: str):
        """Log action for audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user": user,
            "status": status,
            "details": details
        }
        self.audit_log.append(log_entry)

        # Also write to file for persistence
        with open("audit_logs/rbac_audit.log", "a") as f:
            f.write(f"{log_entry['timestamp']} - {user} - {action} - {status} - {details}\n")

    def save_data(self):
        """Save RBAC data to file"""
        data = {
            "users": {k: v.to_dict() for k, v in self.users.items()},
            "roles": {k: v.to_dict() for k, v in self.roles.items()},
            "resources": {k: v.to_dict() for k, v in self.resources.items()},
            "audit_log": self.audit_log[-100:]  # Keep last 100 entries
        }

        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)

    def load_data(self):
        """Load RBAC data from file"""
        if not os.path.exists(self.data_file):
            return

        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)

            # Load users
            for username, user_data in data.get("users", {}).items():
                user = User(user_data["username"], user_data["email"])
                user.roles = set(user_data["roles"])
                user.created_at = datetime.fromisoformat(user_data["created_at"])
                self.users[username] = user

            # Load resources
            for name, resource_data in data.get("resources", {}).items():
                resource = Resource(name, resource_data["owner"], resource_data["resource_type"])
                resource.created_at = datetime.fromisoformat(resource_data["created_at"])
                # Restore ACL
                for user_or_role, perms in resource_data.get("acl", {}).items():
                    resource.acl[user_or_role] = {Permission(p) for p in perms}
                self.resources[name] = resource

            # Load audit log
            self.audit_log = data.get("audit_log", [])

        except Exception as e:
            print(f"Error loading data: {e}")

    def get_user_info(self, username: str) -> Dict:
        """Get detailed user information"""
        if username not in self.users:
            return {}

        user = self.users[username]
        effective_perms = self.get_effective_permissions(username)

        return {
            "username": user.username,
            "email": user.email,
            "roles": list(user.roles),
            "effective_permissions": [p.value for p in effective_perms],
            "created_at": user.created_at.isoformat()
        }
```

### Step 5: File System Demo (45 minutes)

```python
# file_system_demo.py
import os
import shutil
from rbac_system import RBACManager, Permission

class SecureFileSystem:
    def __init__(self, rbac_manager: RBACManager, base_path: str = "files"):
        self.rbac = rbac_manager
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

    def create_file(self, filename: str, content: str, owner: str) -> bool:
        """Create a new file with RBAC protection"""
        # Check if user has write permission
        if not self.rbac.check_permission(owner, "filesystem", Permission.WRITE):
            print(f"❌ Access denied: {owner} cannot create files")
            return False

        file_path = os.path.join(self.base_path, filename)

        try:
            with open(file_path, 'w') as f:
                f.write(content)

            # Register file as resource in RBAC
            self.rbac.create_resource(filename, owner, "file")
            print(f"✅ File {filename} created by {owner}")
            return True

        except Exception as e:
            print(f"❌ Failed to create file: {e}")
            return False

    def read_file(self, filename: str, reader: str) -> Optional[str]:
        """Read file with RBAC check"""
        if not self.rbac.check_permission(reader, filename, Permission.READ):
            print(f"❌ Access denied: {reader} cannot read {filename}")
            return None

        file_path = os.path.join(self.base_path, filename)

        try:
            with open(file_path, 'r') as f:
                content = f.read()
            print(f"✅ File {filename} read by {reader}")
            return content

        except FileNotFoundError:
            print(f"❌ File {filename} not found")
            return None
        except Exception as e:
            print(f"❌ Failed to read file: {e}")
            return None

    def write_file(self, filename: str, content: str, writer: str) -> bool:
        """Write to file with RBAC check"""
        if not self.rbac.check_permission(writer, filename, Permission.WRITE):
            print(f"❌ Access denied: {writer} cannot write to {filename}")
            return False

        file_path = os.path.join(self.base_path, filename)

        try:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✅ File {filename} written by {writer}")
            return True

        except Exception as e:
            print(f"❌ Failed to write file: {e}")
            return False

    def delete_file(self, filename: str, deleter: str) -> bool:
        """Delete file with RBAC check"""
        if not self.rbac.check_permission(deleter, filename, Permission.DELETE):
            print(f"❌ Access denied: {deleter} cannot delete {filename}")
            return False

        file_path = os.path.join(self.base_path, filename)

        try:
            os.remove(file_path)
            # Remove from RBAC system
            if filename in self.rbac.resources:
                del self.rbac.resources[filename]
            print(f"✅ File {filename} deleted by {deleter}")
            return True

        except FileNotFoundError:
            print(f"❌ File {filename} not found")
            return False
        except Exception as e:
            print(f"❌ Failed to delete file: {e}")
            return False

    def list_files(self, lister: str) -> List[str]:
        """List files user can see"""
        files = []
        for filename in os.listdir(self.base_path):
            if self.rbac.check_permission(lister, filename, Permission.READ):
                files.append(filename)

        return files

    def share_file(self, filename: str, with_user: str, permission: Permission, sharer: str):
        """Share file with another user"""
        # Only owner or admin can share
        if not (self.rbac.check_permission(sharer, filename, Permission.ADMIN) or
                (filename in self.rbac.resources and
                 self.rbac.resources[filename].owner == sharer)):
            print(f"❌ Access denied: {sharer} cannot share {filename}")
            return False

        # Grant permission
        if self.rbac.grant_resource_permission(filename, with_user, permission, sharer):
            print(f"✅ {filename} shared with {with_user} ({permission.value} access)")
            return True

        return False

def demo_rbac_filesystem():
    """Demonstrate RBAC file system"""
    print("🚀 RBAC File System Demo")
    print("=" * 40)

    # Initialize RBAC system
    rbac = RBACManager()
    fs = SecureFileSystem(rbac)

    # Create users
    rbac.create_user("alice", "alice@example.com", "user")
    rbac.create_user("bob", "bob@example.com", "user")
    rbac.create_user("admin", "admin@example.com", "admin")
    rbac.create_user("guest", "guest@example.com", "guest")

    print("\n👥 Users created: alice (user), bob (user), admin (admin), guest (guest)")

    # Alice creates a file
    print("\n📄 Alice creates personal_notes.txt")
    fs.create_file("personal_notes.txt", "Alice's personal notes", "alice")

    # Bob tries to read Alice's file (should fail)
    print("\n🔍 Bob tries to read Alice's file")
    content = fs.read_file("personal_notes.txt", "bob")

    # Alice shares file with Bob
    print("\n🤝 Alice shares file with Bob (read access)")
    fs.share_file("personal_notes.txt", "bob", Permission.READ, "alice")

    # Bob reads file (should succeed now)
    print("\n🔍 Bob reads Alice's file (after sharing)")
    content = fs.read_file("personal_notes.txt", "bob")
    if content:
        print(f"   Content: {content}")

    # Guest tries to create file (should fail)
    print("\n❌ Guest tries to create file")
    fs.create_file("guest_file.txt", "Guest content", "guest")

    # Admin creates system file
    print("\n⚙️ Admin creates system configuration")
    fs.create_file("system_config.txt", "System configuration", "admin")

    # Show file listings for different users
    print("\n📋 File listings by user:")
    for user in ["alice", "bob", "guest", "admin"]:
        files = fs.list_files(user)
        print(f"   {user}: {files}")

if __name__ == "__main__":
    demo_rbac_filesystem()
```

## 🐛 Common Issues & Solutions

### Issue: Permission inheritance not working
**Solution**: Ensure `_get_role_permissions()` recursively processes inherited roles

### Issue: Resource ACL conflicts with role permissions
**Solution**: Decide precedence order (usually: resource ACL → role permissions → default)

### Issue: Audit logging performance
**Solution**: Use background logging or limit log size with rotation

### Issue: Complex permission checking
**Solution**: Cache effective permissions for frequently accessed users

## ✅ Testing Workflow

```bash
# Run the demo first
python file_system_demo.py

# Test specific scenarios
python -c "
from rbac_system import RBACManager, Permission
rbac = RBACManager()

# Create test scenario
rbac.create_user('testuser', 'test@example.com', 'user')
rbac.create_resource('secret.txt', 'admin', 'file')

# Test permission check
result = rbac.check_permission('testuser', 'secret.txt', Permission.READ)
print(f'Can testuser read secret.txt? {result}')
"
```

## 📁 Expected File Structure
```
week05-rbac/
├── rbac_system.py              # Core RBAC implementation
├── file_system_demo.py         # Practical demonstration
├── rbac_data.json             # RBAC data storage
├── files/                     # Protected files
│   ├── personal_notes.txt
│   └── system_config.txt
├── audit_logs/
│   └── rbac_audit.log         # Audit trail
├── design_document.md         # RBAC design analysis
└── test_rbac.py              # Test suite
```

## 🎯 Grading Focus Areas

1. **RBAC Components (8 points)**: Proper implementation of users, roles, permissions
2. **Access Control Logic (7 points)**: Correct permission checking and inheritance
3. **Practical Application (5 points)**: Working file system with RBAC
4. **Documentation (5 points)**: Design document and security analysis

## 💡 Pro Tips

1. **Start with Simple Model**: Get basic role checking working first
2. **Test Permission Inheritance**: Ensure role hierarchy works correctly
3. **Use Audit Logging**: Track all access decisions for security
4. **Handle Edge Cases**: What happens with non-existent users/resources?
5. **Consider Performance**: Cache permissions for frequently accessed resources

## 🔍 Security Considerations

### RBAC vs Other Models:
- **DAC (Discretionary)**: Owner controls access
- **MAC (Mandatory)**: System enforces access based on classification
- **RBAC**: Role-based, good for organizations

### Key Security Features:
- **Principle of Least Privilege**: Users get minimal necessary permissions
- **Separation of Duties**: Sensitive operations require multiple roles
- **Audit Trail**: All access decisions are logged

## 🚀 Extension Ideas (Optional)

- Add role hierarchy with constraints
- Implement time-based access controls
- Add context-aware permissions (location, time)
- Create web interface for RBAC management
- Add support for dynamic roles

## ⏱️ Time Management

- **Design the model first**: Don't jump into coding
- **Test each component**: Verify users, roles, permissions separately
- **Use the demo**: It helps verify your implementation works
- **Focus on core logic**: Get permission checking right first

## 🔧 Quick Testing Commands

```python
# Test role inheritance
rbac = RBACManager()
rbac.create_user("test", "test@example.com", "user")
perms = rbac.get_effective_permissions("test")
print(f"User permissions: {[p.value for p in perms]}")

# Test permission checking
result = rbac.check_permission("test", "somefile", Permission.READ)
print(f"Can read: {result}")

# Check audit log
for entry in rbac.audit_log[-5:]:
    print(f"{entry['timestamp']}: {entry['action']} - {entry['status']}")
```

Remember: RBAC is widely used in enterprise systems. Understanding this model will help you design and evaluate access control systems in real applications!