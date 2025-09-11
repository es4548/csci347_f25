# Week 5 Assignment: Role-Based Access Control System

**Due**: End of Week 5  
**Points**: 25 points  
**Estimated Time**: 4 hours  
**Submission**: Submit Pull Request URL to Canvas

---
*Updated for Fall 2025*

## 🎯 Assignment Overview

Implement a Role-Based Access Control (RBAC) system to understand authorization patterns used in enterprise applications.

## 📋 Requirements

### Core Implementation (15 points)

#### 1. RBAC Components (8 points)
- Define roles (admin, user, guest)
- Create permissions model
- Implement role-permission mappings
- Build user-role assignments

#### 2. Access Control Logic (7 points)
- Permission checking functions
- Role hierarchy support
- Resource-based permissions
- Audit logging

### Practical Application (5 points)

Create a simple file system with RBAC:
- Different roles have different file access
- Implement read/write/execute permissions
- Log all access attempts
- Handle permission denied gracefully

### Documentation (5 points)

- Design document explaining your RBAC model
- Security analysis of the implementation
- Comparison with other access control models (MAC, DAC)

## 🔧 Implementation Tips

- Start with a simple flat role model
- Use dictionaries for role/permission mappings
- Consider using decorators for permission checks
- Keep audit logs detailed but secure

## Submission

- `rbac_system.py` - Your RBAC implementation
- `file_system_demo.py` - Practical demonstration
- `design_document.md` - RBAC design and analysis
- `test_rbac.py` - Test suite
