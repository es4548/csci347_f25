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
        self.inherits_from: Set[str] = set()  # Role inherit

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
        # Resource-specific permissions 
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

class RBACManager:
    def __init__(self, data_file: str = "rbac_data.json"):
        self.data_file = data_file
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, Role] = {}
        self.resources: Dict[str, Resource] = {}
        self.audit_log: List[Dict] = []

        # make sure audit_logs directory present
        os.makedirs("audit_logs", exist_ok=True)

        # Initialize default roles
        self._setup_default_roles()
        self.load_data()

    def _setup_default_roles(self):
        #Create default role hierarchy
        # Guest role has minimal permissions
        guest = Role("guest", "Basic read-only access")
        guest.add_permission(Permission.READ)

        # User role has standard user permissions
        user = Role("user", "Standard user access")
        user.add_permission(Permission.READ)
        user.add_permission(Permission.WRITE)
        user.inherit_from("guest")

        # Admin role has full permissions
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
        #Create new user
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
        #Assign role to user
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
        # See if user exists
        if username not in self.users:
            self.log_action("check_permission", username, "FAILED", "User not found")
            return False

        user = self.users[username]

        # Check if resource exists
        resource = self.resources.get(resource_name)

        # Resource owner always has full access
        if resource and resource.owner == username:
            self.log_action("check_permission", username, "SUCCESS",
                        f"Owner access to {resource_name}")
            return True

        # Resource-specific ACL (user or role)
        if resource:
            for role_or_user in [username] + list(user.roles):
                if role_or_user in resource.acl and permission in resource.acl[role_or_user]:
                    self.log_action("check_permission", username, "SUCCESS", f"ACL access to {resource_name}")
                    return True

        # Check role-based permissions for non-resource-specific actions
        effective_permissions = self.get_effective_permissions(username)
        has_permission = permission in effective_permissions and not resource

        status = "SUCCESS" if has_permission else "DENIED"
        self.log_action("check_permission", username, status, f"Permission {permission.value} for {resource_name}")

        return has_permission

    def get_effective_permissions(self, username: str) -> Set[Permission]:
        #Get all effective permissions for a user
        if username not in self.users:
            return set()

        permissions = set()
        user = self.users[username]

        # get permissions from all roles
        for role_name in user.roles:
            permissions.update(self._get_role_permissions(role_name))

        return permissions

    def _get_role_permissions(self, role_name: str) -> Set[Permission]:
        #get all permissions for a role 
        if role_name not in self.roles:
            return set()

        role = self.roles[role_name]
        permissions = role.permissions.copy()

        # Add inherited permissions
        for inherited_role in role.inherits_from:
            permissions.update(self._get_role_permissions(inherited_role))

        return permissions

    def create_resource(self, name: str, owner: str, resource_type: str = "file") -> bool:
        #Create new resource
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
        #Grant permission on specific resource
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
        #Log action for audit trail
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user": user,
            "status": status,
            "details": details
        }
        self.audit_log.append(log_entry)

        # write to file for persistence
        try:
            with open("audit_logs/rbac_audit.log", "a") as f:
                f.write(f"{log_entry['timestamp']} - {user} - {action} - {status} - {details}\n")
        except Exception:
            # Best-effort logging; avoid raising from within logger
            pass

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
        #Load RBAC data from file 
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
                resource = Resource(name, resource_data["owner"], resource_data.get("resource_type", "file"))
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
        #Get detailed user information
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
