# pan_compliance_checks.py

import xml.etree.ElementTree as ET

# Define structure for security findings
class Finding:
    def __init__(self, issue, description, check_status, risk, fix_type, remediation):
        self.issue = issue
        self.description = description
        self.status = check_status
        self.risk = risk
        self.fix_type = fix_type
        self.remediation = remediation


# --- Compliance Check Functions ---
def check_local_admin_password_hash(root, NS):
    """CIS 1.4.3: Ensure no admin accounts use weak authentication."""
    xpath_query = ".//ns:local-user-database/ns:user/ns:entry"
    weak_users = []

    for user_entry in root.findall(xpath_query, NS):
        username = user_entry.get('name')
        if user_entry.find('ns:phash', NS) is None:
            weak_users.append(username)

    if weak_users:
        return Finding(
            issue="Weak Local User Hashing",
            description=f"Admin accounts without secure hashes: {', '.join(weak_users)}.",
            check_status="Fail",
            risk="Critical",
            fix_type="Quick",
            remediation="Reset the passwords to regenerate secure hashes."
        )
    return Finding("Weak Local User Hashing", "", "Pass", "Critical", "Quick", "All users use secure password hashing.")


def check_https_only_management(root, NS):
    """CIS 2.1.2: Ensure management access is restricted to HTTPS."""
    profiles = root.findall(".//ns:management-profile/ns:entry", NS)
    http_enabled = any(p.find(".//ns:allowed-methods/ns:http", NS) is not None for p in profiles)
    https_enabled = any(p.find(".//ns:allowed-methods/ns:https", NS) is not None for p in profiles)

    if http_enabled:
        return Finding(
            issue="Insecure HTTP Management Enabled",
            description="HTTP is enabled in at least one management profile.",
            check_status="Fail",
            risk="High",
            fix_type="Quick",
            remediation="Remove 'http' from 'allowed-methods' in management profiles."
        )
    if not https_enabled and profiles:
        return Finding(
            issue="No HTTPS Management Enabled",
            description="HTTPS is not explicitly enabled in management profiles.",
            check_status="Fail",
            risk="High",
            fix_type="Quick",
            remediation="Ensure HTTPS is enabled in all management profiles."
        )

    return Finding("Insecure HTTP Management Enabled", "", "Pass", "High", "Quick", "Management restricted to HTTPS.")


def check_ssh_service_disabled(root, NS):
    """CIS 2.1.6: Ensure SSH is disabled for management access unless required."""
    ssh_entries = root.findall(".//ns:management-profile/ns:entry/ns:allowed-methods/ns:ssh", NS)

    if ssh_entries:
        return Finding(
            issue="SSH Management Enabled",
            description="SSH management access is enabled in one or more profiles.",
            check_status="Manual",
            risk="Medium",
            fix_type="Planned",
            remediation="Remove SSH from management profiles if not required."
        )
    return Finding("SSH Management Enabled", "", "Pass", "Medium", "Planned", "SSH management appears disabled.")


def check_security_policy_manual(root, NS):
    """CIS 3.1.1: Review security policies manually."""
    rules = root.findall(".//ns:security/ns:rules/ns:entry", NS)
    count = len(rules)

    if count > 0:
        return Finding(
            issue="Security Policy Review Required",
            description=f"{count} security rules found. Manual review required.",
            check_status="Manual",
            risk="Critical",
            fix_type="Involved",
            remediation="Ensure a final deny-all rule and proper logging on all rules."
        )
    return Finding("Security Policy Review Required", "", "Pass", "Critical", "Involved", "No user-defined security rules found.")


def run_all_checks_panos(root, NS):
    """Run all compliance checks and return non-pass findings."""
    results = [
        check_local_admin_password_hash(root, NS),
        check_https_only_management(root, NS),
        check_ssh_service_disabled(root, NS),
        check_security_policy_manual(root, NS)
    ]
    return [r for r in results if r.status != "Pass"]
