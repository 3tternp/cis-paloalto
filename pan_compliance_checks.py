# pan_compliance_checks.py

import xml.etree.ElementTree as ET

# Define the common PAN-OS namespace prefix and URI. 
NS = {'ns': 'http://xml.paloaltonetworks.com/config/1.0'}

# Global list to store all registered check functions
REGISTERED_CHECKS = []

# Decorator to automatically register check functions
def register_check(cis_id, level, issue, risk, remediation):
    def decorator(func):
        func.cis_id = cis_id
        func.level = level
        func.issue_template = issue
        func.risk = risk
        func.remediation = remediation
        REGISTERED_CHECKS.append(func)
        return func
    return decorator

# Define the structure for a security finding/check result
class Finding:
    def __init__(self, cis_id, level, issue, description, check_status, risk, remediation):
        self.cis_id = cis_id
        self.level = level
        self.issue = issue
        self.description = description
        self.status = check_status  # Pass, Fail, Manual
        self.risk = risk            # Critical, High, Medium, Low
        self.remediation = remediation
        self.fix_type = "Planned" # Simplifying fix_type based on the detailed Remediation/Risk

# Helper function to create a Finding object
def create_finding(func, status, description="", detail=""):
    issue_desc = func.issue_template.replace("– ", "– ") + (f" ({detail})" if detail else "")
    return Finding(
        cis_id=func.cis_id,
        level=func.level,
        issue=func.issue_template,
        description=description or f"Check Status: {status}. {func.issue_template}",
        check_status=status,
        risk=func.risk,
        remediation=func.remediation
    )


# ====================================================================
# CIS SECTION 1: DEVICE SETUP AND SYSTEM INTEGRITY
# ====================================================================

@register_check(
    cis_id="1.1.1",
    level="Level 1",
    issue="Ensure NTP Server is Configured",
    risk="Medium",
    remediation="Configure at least one NTP server under Device → Setup → Services → NTP."
)
def check_ntp_server(root):
    """Checks for the presence of at least one NTP server."""
    xpath = ".//ns:ntp-servers/ns:ntp-server"
    if root.findall(xpath, NS):
        return create_finding(check_ntp_server, "Pass")
    else:
        return create_finding(check_ntp_server, "Fail",
                              description="No NTP server configured in system setup.")

@register_check(
    cis_id="1.1.2",
    level="Level 1",
    issue="Ensure Management Interface Profile is Configured",
    risk="High",
    remediation="Configure a dedicated Management Profile to restrict access protocols (e.g., allow only HTTPS/SSH) and apply it to the management interface."
)
def check_management_profile(root):
    """Checks for the presence of a named management profile."""
    xpath = ".//ns:management-profile/ns:entry"
    if root.findall(xpath, NS):
        return create_finding(check_management_profile, "Pass")
    else:
        return create_finding(check_management_profile, "Manual",
                              description="No named Management Profile found. Manually verify if the default 'allow-all' profile is in use or if configuration is implicit.")

@register_check(
    cis_id="1.2.1",
    level="Level 1",
    issue="Ensure Device Name is Configured",
    risk="Low",
    remediation="Set the hostname under Device → Setup → Management → General Settings."
)
def check_hostname(root):
    """Checks if a device hostname is configured."""
    xpath = ".//ns:hostname"
    if root.find(xpath, NS) is not None and root.find(xpath, NS).text:
        return create_finding(check_hostname, "Pass")
    else:
        return create_finding(check_hostname, "Fail",
                              description="Hostname is not configured or is using a default value.")

@register_check(
    cis_id="1.2.4",
    level="Level 1",
    issue="Ensure Log Forwarding is Configured",
    risk="Medium",
    remediation="Configure at least one Log Forwarding Profile to send system, traffic, and threat logs to an external collector/SIEM (e.g., Panorama, Syslog, SNMP)."
)
def check_log_forwarding(root):
    """Checks for the presence of Log Forwarding Profiles."""
    xpath = ".//ns:log-forwarding/ns:entry"
    if root.findall(xpath, NS):
        return create_finding(check_log_forwarding, "Pass")
    else:
        return create_finding(check_log_forwarding, "Fail",
                              description="No Log Forwarding Profile is defined to send logs externally.")


# ====================================================================
# CIS SECTION 2: MANAGEMENT ACCESS AND AUTHENTICATION
# ====================================================================

@register_check(
    cis_id="2.1.1",
    level="Level 1",
    issue="Ensure Local Admin Accounts Use Secure Authentication",
    risk="Critical",
    remediation="Ensure all local admin accounts have passwords reset to force the generation of a secure hash (phash)."
)
def check_local_admin_password_hash(root):
    """Checks for presence of phash (secure hash) for local admin accounts."""
    xpath = ".//ns:local-user-database/ns:user/ns:entry"
    
    weak_users = []
    for user_entry in root.findall(xpath, NS):
        username = user_entry.get('name')
        if user_entry.find('ns:phash', NS) is None:
            weak_users.append(username)
            
    if weak_users:
        return create_finding(check_local_admin_password_hash, "Fail",
                              description=f"Admin account(s) are configured without a secure hash (phash). Check users: {', '.join(weak_users)}.")
    return create_finding(check_local_admin_password_hash, "Pass")

@register_check(
    cis_id="2.1.2",
    level="Level 1",
    issue="Ensure HTTP is Disabled for Management",
    risk="High",
    remediation="Disable 'http' in all management profiles under Network → Network Profiles → Management Profile."
)
def check_https_only_management(root):
    """Checks all management profiles for the presence of the 'http' service."""
    xpath_http = ".//ns:management-profile/ns:entry/ns:allowed-methods/ns:http"
    
    if root.findall(xpath_http, NS):
        return create_finding(check_https_only_management, "Fail",
                              description="HTTP is enabled in at least one management profile, allowing cleartext login credentials.")
    
    return create_finding(check_https_only_management, "Pass")

@register_check(
    cis_id="2.1.3",
    level="Level 1",
    issue="Ensure Telnet is Disabled for Management",
    risk="Critical",
    remediation="Disable 'telnet' in all management profiles under Network → Network Profiles → Management Profile."
)
def check_telnet_disabled(root):
    """Checks all management profiles for the presence of the 'telnet' service."""
    xpath_telnet = ".//ns:management-profile/ns:entry/ns:allowed-methods/ns:telnet"
    
    if root.findall(xpath_telnet, NS):
        return create_finding(check_telnet_disabled, "Fail",
                              description="Telnet is enabled in at least one management profile.")
    
    return create_finding(check_telnet_disabled, "Pass")

@register_check(
    cis_id="2.1.4",
    level="Level 2",
    issue="Ensure Insecure SNMP Version is Disabled",
    risk="Medium",
    remediation="Only use SNMPv3 or disable SNMP entirely. Remove SNMPv1/v2c access from management profiles."
)
def check_snmp_version(root):
    """Checks if SNMP v1 or v2c is explicitly allowed in any profile."""
    xpath_v1 = ".//ns:management-profile/ns:entry/ns:snmp-config/ns:v1-v2c"
    
    if root.findall(xpath_v1, NS):
        return create_finding(check_snmp_version, "Manual",
                              description="SNMP v1/v2c is configured. Manually verify access strings are complex and that SNMP is only used on secured interfaces.")
    
    return create_finding(check_snmp_version, "Pass")

@register_check(
    cis_id="2.2.1",
    level="Level 1",
    issue="Ensure Authentication Profile is Configured",
    risk="Critical",
    remediation="Integrate the firewall with an external directory service (e.g., LDAP, RADIUS, TACACS+) and configure an Authentication Profile under Device → Authentication Profile."
)
def check_auth_profile_exists(root):
    """Checks for the presence of at least one Authentication Profile entry (external authentication)."""
    xpath = ".//ns:authentication-profile/ns:entry"
    if root.findall(xpath, NS):
        return create_finding(check_auth_profile_exists, "Pass")
    else:
        return create_finding(check_auth_profile_exists, "Fail",
                              description="No external Authentication Profile is configured, relying solely on local accounts for management access.")

@register_check(
    cis_id="2.2.2",
    level="Level 1",
    issue="Ensure Local Database is NOT Used for Device Access",
    risk="High",
    remediation="Set the Authentication Profile to use for all access types (Setup, GlobalProtect, Captive Portal) to an external profile, minimizing reliance on the local database."
)
def check_local_database_usage(root):
    """Checks if the local database is selected as the default authentication mechanism."""
    # Look for the default auth profile configuration (often found under global settings)
    xpath = ".//ns:authentication-profile-type[ns:local-database]"
    
    if root.findall(xpath, NS):
        return create_finding(check_local_database_usage, "Manual",
                              description="The 'local-database' is explicitly referenced as the authentication source for some functions. Manual review is required to ensure it is not used for primary device management login.")
    
    return create_finding(check_local_database_usage, "Pass")

@register_check(
    cis_id="2.3.1",
    level="Level 1",
    issue="Ensure Admin Role Separation is Configured",
    risk="Medium",
    remediation="Configure separate Admin Role Profiles with minimal privileges for different administrative tasks. Apply them to each admin account (local or external)."
)
def check_admin_role_profile(root):
    """Checks for the presence of custom Admin Role Profiles."""
    # Check for custom admin role entries (default roles are always present)
    xpath = ".//ns:admin-role/ns:entry[not(ns:default-role)]"
    if root.findall(xpath, NS):
        return create_finding(check_admin_role_profile, "Pass")
    else:
        return create_finding(check_admin_role_profile, "Manual",
                              description="No custom Admin Role Profiles found. Manually verify if built-in 'Superuser' or 'Device Admin' roles are being used excessively.")

@register_check(
    cis_id="2.4.1",
    level="Level 1",
    issue="Ensure Minimum Password Complexity is Configured",
    risk="Medium",
    remediation="Configure password complexity rules under Device → Setup → Management → Authentication Settings."
)
def check_password_complexity(root):
    """Checks if password complexity rules are explicitly configured and non-zero."""
    # Example check for minimum password length (often required by CIS)
    xpath_length = ".//ns:min-password-length"
    
    length_element = root.find(xpath_length, NS)
    if length_element is None or int(length_element.text or 0) < 8:
        return create_finding(check_password_complexity, "Fail",
                              description="Minimum password length is not configured or is less than the recommended 8 characters.")
    
    return create_finding(check_password_complexity, "Pass")

# ====================================================================
# CIS SECTION 3: SECURITY POLICIES AND PROFILES
# ====================================================================

@register_check(
    cis_id="3.1.1",
    level="Level 1",
    issue="Ensure Security Policy Has a Final Deny Rule",
    risk="Critical",
    remediation="Ensure the last rule in the security policy is a 'Deny' action that logs all traffic, enforcing the 'Deny by Default' principle."
)
def check_security_policy_final_deny(root):
    """Manually checks policy rules, focusing on the implicit final deny."""
    # This check is primarily manual due to the difficulty of programmatically confirming the *last* rule's action.
    xpath_rules = ".//ns:security/ns:rules/ns:entry"
    num_rules = len(root.findall(xpath_rules, NS))
    
    if num_rules > 0:
        return create_finding(check_security_policy_final_deny, "Manual",
                              description=f"The configuration contains {num_rules} user-defined security policy rules. Manually verify the **last** rule is a Deny/Drop rule for all traffic (the explicit final deny).")
    return create_finding(check_security_policy_final_deny, "Pass", detail="No user-defined security policies found (relying on implicit deny).")


@register_check(
    cis_id="3.1.2",
    level="Level 1",
    issue="Ensure Policy Rules Use Least Privilege Principle",
    risk="Critical",
    remediation="Review all Security Policy rules to ensure they only allow specific applications, users, and destinations required for business operations. Minimize the use of 'any/all' rules."
)
def check_policy_least_privilege(root):
    """Manual check requiring analyst review of rule specificity."""
    return create_finding(check_policy_least_privilege, "Manual",
                          description="Policy rules are present. Manually verify that 'any/any' rules are justified and that policies use specific users, applications, and services.")

@register_check(
    cis_id="3.1.3",
    level="Level 1",
    issue="Ensure Logging is Enabled on Policy Rules",
    risk="Medium",
    remediation="Ensure the 'Log at Session End' option is enabled for all required Security Policy rules, especially Deny rules, to ensure proper monitoring and forensics."
)
def check_policy_logging_enabled(root):
    """Checks for the presence of rules that explicitly disable logging."""
    # Look for any rule entry that has a 'no' logging action
    xpath_no_log = ".//ns:security/ns:rules/ns:entry[ns:action='allow' and not(ns:log-end)]"
    
    non_logging_rules = root.findall(xpath_no_log, NS)
    if non_logging_rules:
        rule_names = [r.get('name') for r in non_logging_rules]
        return create_finding(check_policy_logging_enabled, "Manual",
                              description=f"Allow rules found without explicit 'log-end' configuration. Review rules: {', '.join(rule_names)}.")
    
    return create_finding(check_policy_logging_enabled, "Pass")


@register_check(
    cis_id="3.2.1",
    level="Level 1",
    issue="Ensure Vulnerability Protection Profile is Configured and Applied",
    risk="Critical",
    remediation="Configure a Vulnerability Protection Profile (Anti-Spyware) and ensure it is applied to all relevant Security Policy rules."
)
def check_vulnerability_profile(root):
    """Checks for the presence of the default security profile group with a vulnerability profile."""
    # Look for the default profile group and check if a vulnerability profile is linked
    xpath = ".//ns:profile-setting/ns:group/ns:entry/ns:vulnerability-protection-profile"
    if root.findall(xpath, NS):
        return create_finding(check_vulnerability_profile, "Pass")
    else:
        return create_finding(check_vulnerability_profile, "Fail",
                              description="No Vulnerability Protection Profile is configured in the default profile group.")

@register_check(
    cis_id="3.2.2",
    level="Level 1",
    issue="Ensure Anti-Spyware Profile is Configured and Applied",
    risk="Critical",
    remediation="Configure an Anti-Spyware Profile and ensure it is applied to all relevant Security Policy rules."
)
def check_anti_spyware_profile(root):
    """Checks for the presence of the default security profile group with an anti-spyware profile."""
    xpath = ".//ns:profile-setting/ns:group/ns:entry/ns:anti-spyware-profile"
    if root.findall(xpath, NS):
        return create_finding(check_anti_spyware_profile, "Pass")
    else:
        return create_finding(check_anti_spyware_profile, "Fail",
                              description="No Anti-Spyware Profile is configured in the default profile group.")

# --- Additional Checks to meet the ~25 target ---

@register_check(
    cis_id="1.3.1",
    level="Level 1",
    issue="Ensure Administrative User Timeouts are Configured",
    risk="Medium",
    remediation="Set a 60-minute or less idle timeout for CLI and Web interfaces under Device → Setup → Management → General Settings."
)
def check_admin_timeout(root):
    """Checks if the administrative timeout is set (e.g., < 60 minutes)."""
    xpath = ".//ns:cli/ns:idle-timeout"
    timeout_element = root.find(xpath, NS)
    
    # CIS recommends 60 minutes or less. Default can be 0 (no timeout).
    if timeout_element is None or int(timeout_element.text or 0) > 3600: # 3600 seconds = 60 minutes
        return create_finding(check_admin_timeout, "Fail",
                              description="CLI/Web idle timeout is missing or set to longer than 60 minutes.")
    return create_finding(check_admin_timeout, "Pass")

@register_check(
    cis_id="1.4.1",
    level="Level 1",
    issue="Ensure Timezone is Configured",
    risk="Low",
    remediation="Set the correct timezone under Device → Setup → Management → General Settings to ensure log consistency."
)
def check_timezone(root):
    """Checks if a timezone is explicitly configured."""
    xpath = ".//ns:timezone"
    if root.find(xpath, NS) is not None and root.find(xpath, NS).text:
        return create_finding(check_timezone, "Pass")
    else:
        return create_finding(check_timezone, "Fail",
                              description="Timezone is not configured.")

@register_check(
    cis_id="1.5.1",
    level="Level 2",
    issue="Ensure Master Key is Protected by a Password",
    risk="Critical",
    remediation="Set a Master Key password under Device → Setup → Management → Master Key. This is required to encrypt saved credentials."
)
def check_master_key_password(root):
    """Checks for the presence of the master key password setting."""
    # A true check is difficult, but we look for the configuration tag itself
    xpath = ".//ns:master-key-settings/ns:master-key-password"
    
    if root.find(xpath, NS) is None:
        return create_finding(check_master_key_password, "Manual",
                              description="Master Key password configuration is missing. Manually verify Master Key encryption status on the device.")
    return create_finding(check_master_key_password, "Pass")


@register_check(
    cis_id="2.5.1",
    level="Level 1",
    issue="Ensure Password-based Authentication is Disabled for SSH",
    risk="High",
    remediation="Disable password-based authentication for SSH access and enforce key-based authentication for management."
)
def check_ssh_password_auth(root):
    """Checks if password-based authentication is explicitly disabled for SSH."""
    xpath = ".//ns:sshd/ns:password-auth"
    
    auth_element = root.find(xpath, NS)
    # The default behavior can be implicit, so we check for explicit configuration.
    if auth_element is not None and auth_element.text == 'yes':
        return create_finding(check_ssh_password_auth, "Fail",
                              description="Password-based authentication is explicitly enabled for SSH access.")
    
    return create_finding(check_ssh_password_auth, "Manual",
                          description="Password authentication for SSH is not explicitly disabled. Manually verify the SSH profile.")

@register_check(
    cis_id="3.3.1",
    level="Level 1",
    issue="Ensure Antivirus Profile is Configured and Applied",
    risk="Critical",
    remediation="Configure an Antivirus Profile and ensure it is applied to all relevant Security Policy rules."
)
def check_antivirus_profile(root):
    """Checks for the presence of the default security profile group with an antivirus profile."""
    xpath = ".//ns:profile-setting/ns:group/ns:entry/ns:virus-protection-profile"
    if root.findall(xpath, NS):
        return create_finding(check_antivirus_profile, "Pass")
    else:
        return create_finding(check_antivirus_profile, "Fail",
                              description="No Antivirus Profile is configured in the default profile group.")

@register_check(
    cis_id="3.3.2",
    level="Level 1",
    issue="Ensure URL Filtering Profile is Configured and Applied",
    risk="Medium",
    remediation="Configure a URL Filtering Profile and ensure it is applied to all relevant Security Policy rules."
)
def check_url_filtering_profile(root):
    """Checks for the presence of the default security profile group with a URL filtering profile."""
    xpath = ".//ns:profile-setting/ns:group/ns:entry/ns:url-filtering-profile"
    if root.findall(xpath, NS):
        return create_finding(check_url_filtering_profile, "Pass")
    else:
        return create_finding(check_url_filtering_profile, "Fail",
                              description="No URL Filtering Profile is configured in the default profile group.")

@register_check(
    cis_id="3.3.3",
    level="Level 1",
    issue="Ensure File Blocking Profile is Configured and Applied",
    risk="High",
    remediation="Configure a File Blocking Profile and ensure it is applied to all relevant Security Policy rules to prevent unauthorized file transfers."
)
def check_file_blocking_profile(root):
    """Checks for the presence of the default security profile group with a file blocking profile."""
    xpath = ".//ns:profile-setting/ns:group/ns:entry/ns:file-blocking-profile"
    if root.findall(xpath, NS):
        return create_finding(check_file_blocking_profile, "Pass")
    else:
        return create_finding(check_file_blocking_profile, "Fail",
                              description="No File Blocking Profile is configured in the default profile group.")

@register_check(
    cis_id="3.4.1",
    level="Level 1",
    issue="Ensure DoS Protection Profile is Configured and Applied",
    risk="Critical",
    remediation="Configure a Zone Protection Profile with DoS protection enabled for external zones, and a DoS Protection Policy for critical servers."
)
def check_dos_profile(root):
    """Checks for the presence of a DoS Protection Profile."""
    xpath = ".//ns:dos-protection-profile/ns:entry"
    if root.findall(xpath, NS):
        return create_finding(check_dos_profile, "Pass")
    else:
        return create_finding(check_dos_profile, "Fail",
                              description="No DoS Protection Profile is configured.")


# --- RUN ALL CHECKS ---

def run_all_checks_panos(root):
    """Executes all defined PAN-OS security checks on the XML root."""
    results = []
    
    for check_func in REGISTERED_CHECKS:
        try:
            finding = check_func(root)
            if finding.status != "Pass":
                results.append(finding)
        except Exception as e:
            # Handle potential XML structure errors gracefully for a single check
            results.append(
                Finding(
                    cis_id=getattr(check_func, 'cis_id', 'N/A'),
                    level=getattr(check_func, 'level', 'N/A'),
                    issue=f"Check Execution Error: {check_func.issue_template}",
                    description=f"Error running check {check_func.__name__}: {e}. Configuration structure may be non-standard.",
                    check_status="Manual",
                    risk="High",
                    remediation="Manual review of the configuration element is required."
                )
            )
            
    return results

def get_total_checks():
    """Returns the total number of registered checks."""
    return len(REGISTERED_CHECKS)