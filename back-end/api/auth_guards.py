"""
RBAC Guard Definitions
Predefined role checkers for common permission levels.
"""

from api.auth import RoleChecker

# Define permission levels for different operations
# Admin: Full system access
allow_admin = RoleChecker(allowed_roles=["admin"])

# Analyst: Can view data and generate reports
allow_analyst = RoleChecker(allowed_roles=["admin", "analyst"])

# Viewer: Read-only access
allow_viewer = RoleChecker(allowed_roles=["admin", "analyst", "viewer"])

# System Operations: Only admin
allow_system_operations = RoleChecker(allowed_roles=["admin"])

# Rule Management: Only admin
allow_rule_management = RoleChecker(allowed_roles=["admin"])

# Incident Management: Admin and analyst
allow_incident_management = RoleChecker(allowed_roles=["admin", "analyst"])

# ML Model Management: Only admin
allow_ml_model_management = RoleChecker(allowed_roles=["admin"])
