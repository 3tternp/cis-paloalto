"""
Comprehensive Palo Alto CIS v1.1.0 Configuration Auditor (Automated + Manual Review)

Fixes:
- Updated UTC timestamp to use timezone-aware objects to prevent DeprecationWarning.
- Added safe exit for GUI interruption (KeyboardInterrupt handling).

Usage:
 python pa_cis_audit_full_gui.py
"""

import os
import sys
import subprocess
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import filedialog, messagebox

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        __import__(package)

for pkg in ['pandas', 'matplotlib', 'jinja2']:
    install_and_import(pkg)

import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template

def load_xml(path):
    tree = ET.parse(path)
    return tree.getroot()

def xpath_find(root, path):
    parts = [p for p in path.strip('/').split('/') if p]
    node = root
    for part in parts:
        node = node.find(part)
        if node is None:
            return None
    return node

SEVERITY_BY_CHECK = {
    '1.1-disable-http-telnet': ('critical', 'quick'),
    '1.2-disable-snmp-or-use-v3': ('high', 'planned'),
    '1.3-ntp-configured': ('medium', 'planned'),
    '1.4-permitted-ip': ('high', 'involved'),
    '1.5-login-banner': ('medium', 'manual'),
    '2.1-user-id-probe': ('medium', 'manual'),
    '3.1-ha-enabled': ('medium', 'manual'),
    '4.1-dynamic-updates': ('medium', 'manual'),
    '6.1-antivirus': ('high', 'manual'),
    '6.2-vulnerability-protection': ('high', 'manual'),
    '6.3-url-filtering': ('high', 'manual'),
    '7.1-policy-deny-all': ('high', 'manual'),
    '7.2-log-forwarding': ('medium', 'manual'),
}

def check_disable_http_telnet(root):
    node = xpath_find(root, '/config/devices/entry/deviceconfig/system/service')
    if node is None:
        return False, 'Management service node not found', ''
    http = node.find('disable-http')
    telnet = node.find('disable-telnet')
    passed = (http is not None and http.text == 'yes') and (telnet is not None and telnet.text == 'yes')
    return passed, 'Ensure HTTP and Telnet are disabled on management interface.', 'set deviceconfig system service disable-http yes\nset deviceconfig system service disable-telnet yes\ncommit'

def check_disable_snmp_or_use_v3(root):
    node = xpath_find(root, '/config/devices/entry/deviceconfig/system/snmp')
    if node is None:
        return True, 'SNMP not configured (OK)', ''
    community = node.find('community')
    v3 = node.find('v3')
    passed = v3 is not None and (community is None or len(community) == 0)
    return passed, 'Ensure SNMP is disabled or configured for SNMPv3.', 'set deviceconfig system service disable-snmp yes\ncommit'

def check_ntp_configured(root):
    node = xpath_find(root, '/config/devices/entry/deviceconfig/system/ntp')
    if node is None:
        return False, 'NTP not configured', 'set deviceconfig system ntp-servers primary-1 ip-address <ip>\ncommit'
    servers = node.findall('server')
    return bool(servers), 'Ensure NTP servers are configured.', 'set deviceconfig system ntp-servers primary-1 ip-address <ip>'

def check_management_permitted_ip(root):
    node = xpath_find(root, '/config/devices/entry/deviceconfig/system/permitted-ip')
    if node is None:
        return False, 'Permitted IP not configured', 'set deviceconfig system permitted-ip <trusted-subnet>\ncommit'
    txt = ''.join(node.itertext()).strip()
    if '0.0.0.0' in txt or txt == '':
        return False, 'Permitted IP allows any (0.0.0.0/0)', 'Restrict management access to admin network'
    return True, 'Management permitted-ip configured properly', ''

def manual_check(desc):
    return None, f'{desc} (Manual Verification Required)', 'Refer to CIS benchmark section for manual verification guidance.'

CHECKS = {
    '1.1-disable-http-telnet': check_disable_http_telnet,
    '1.2-disable-snmp-or-use-v3': check_disable_snmp_or_use_v3,
    '1.3-ntp-configured': check_ntp_configured,
    '1.4-permitted-ip': check_management_permitted_ip,
    '1.5-login-banner': lambda r: manual_check('Verify system login banner text matches approved warning message.'),
    '2.1-user-id-probe': lambda r: manual_check('Verify User-ID WMI probing and server settings are configured securely.'),
    '3.1-ha-enabled': lambda r: manual_check('Check that HA synchronization is configured correctly.'),
    '4.1-dynamic-updates': lambda r: manual_check('Confirm dynamic updates (AV, Threat, App) are scheduled automatically.'),
    '6.1-antivirus': lambda r: manual_check('Ensure antivirus profile is applied to relevant security rules.'),
    '6.2-vulnerability-protection': lambda r: manual_check('Ensure vulnerability protection profile is applied to policies.'),
    '6.3-url-filtering': lambda r: manual_check('Ensure URL filtering policy is configured.'),
    '7.1-policy-deny-all': lambda r: manual_check('Verify existence of explicit deny-all rule at end of policy set.'),
    '7.2-log-forwarding': lambda r: manual_check('Ensure all security policies have log forwarding enabled.'),
}

HTML_TEMPLATE = """
<html>
<head><title>Palo Alto CIS v1.1.0 Compliance Report</title>
<style>
body { font-family: Arial; background: #f5f5f5; margin: 20px; }
h1 { color: #222; }
h2 { color: #444; margin-top: 30px; }
.card { display:inline-block; margin:10px; padding:10px 20px; border-radius:8px; color:#fff; }
.green { background:#2e7d32; }
.red { background:#c62828; }
.gold { background:#b58900; }
.manual { background:#6c757d; }
table { border-collapse:collapse; width:100%; background:white; }
th,td{border:1px solid #ccc; padding:8px;}
th{background:#333;color:#fff;}
pre{white-space:pre-wrap;}
</style>
</head>
<body>
<h1>Palo Alto Firewall CIS v1.1.0 Benchmark Audit Report</h1>
<p><b>Generated:</b> {{gen}}</p>
<div>
<div class="card green">Passed: {{passed}}</div>
<div class="card red">Failed: {{failed}}</div>
<div class="card gold">Total: {{total}}</div>
<div class="card manual">Manual Reviews: {{manual}}</div>
</div>
<img src="passfail.png" width="400">
{% for section, section_rows in grouped.items() %}
<h2>Section {{section}}</h2>
<table>
<tr><th>Check ID</th><th>Status</th><th>Risk</th><th>Fix Type</th><th>Description</th><th>Remediation</th></tr>
{% for r in section_rows %}
<tr>
<td>{{r['check']}}</td>
<td style="color:{{r['color']}}">{{r['status']}}</td>
<td>{{r['risk']}}</td>
<td>{{r['fix']}}</td>
<td>{{r['desc']}}</td>
<td><pre>{{r['remed']}}</pre></td>
</tr>
{% endfor %}
</table>
{% endfor %}
</body></html>
"""

def run_checks(root):
    results = []
    for cid, func in CHECKS.items():
        p, d, r = func(root)
        risk, fix = SEVERITY_BY_CHECK.get(cid, ('medium', 'planned'))
        if p is None:
            status, color = 'MANUAL', 'gray'
        elif p:
            status, color = 'PASS', 'green'
        else:
            status, color = 'FAIL', 'red'
        section = cid.split('.')[0]
        results.append({'section': section, 'check': cid, 'status': status, 'color': color, 'risk': risk, 'fix': fix, 'desc': d, 'remed': r})
    return results

def generate_report(data, outdir):
    os.makedirs(outdir, exist_ok=True)
    df = pd.DataFrame(data)
    df.to_csv(os.path.join(outdir, 'cis_v1.1.0_results.csv'), index=False)

    counts = df['status'].value_counts()
    plt.figure()
    counts.plot(kind='bar', title='CIS Check Results Summary')
    plt.ylabel('Count')
    plt.savefig(os.path.join(outdir, 'passfail.png'))

    grouped = {sec: df[df['section'] == sec].to_dict(orient='records') for sec in sorted(df['section'].unique())}
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(
        gen=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        grouped=grouped,
        passed=(df['status'] == 'PASS').sum(),
        failed=(df['status'] == 'FAIL').sum(),
        manual=(df['status'] == 'MANUAL').sum(),
        total=len(df)
    )

    html_path = os.path.join(outdir, 'CIS_Report.html')
    with open(html_path, 'w') as f:
        f.write(html)
    return html_path

def browse_input():
    path = filedialog.askopenfilename(filetypes=[('XML files', '*.xml')])
    if path:
        input_var.set(path)

def browse_output():
    path = filedialog.askdirectory()
    if path:
        output_var.set(path)

def run_audit():
    inp, out = input_var.get(), output_var.get()
    if not inp or not out:
        messagebox.showerror('Error', 'Please select input XML and output directory.')
        return
    try:
        root = load_xml(inp)
        data = run_checks(root)
        html_path = generate_report(data, out)
        messagebox.showinfo('Audit Complete', f'Report generated successfully:\n{html_path}')
    except KeyboardInterrupt:
        messagebox.showwarning('Stopped', 'Audit process interrupted by user.')
        sys.exit(0)
    except Exception as e:
        messagebox.showerror('Error', str(e))

root_tk = tk.Tk()
root_tk.title('Palo Alto CIS v1.1.0 Configuration Auditor')
root_tk.geometry('520x270')

input_var = tk.StringVar()
output_var = tk.StringVar()

tk.Label(root_tk, text='Select Palo Alto XML Config:').pack(pady=5)
tk.Entry(root_tk, textvariable=input_var, width=50).pack()
tk.Button(root_tk, text='Browse', command=browse_input).pack(pady=5)

tk.Label(root_tk, text='Select Output Directory:').pack(pady=5)
tk.Entry(root_tk, textvariable=output_var, width=50).pack()
tk.Button(root_tk, text='Browse', command=browse_output).pack(pady=5)

tk.Button(root_tk, text='Run CIS Audit', bg='green', fg='white', command=run_audit).pack(pady=10)

tk.Label(root_tk, text='Report grouped by CIS section (1.x, 2.x, etc.) with charts and manual checks').pack()

try:
    root_tk.mainloop()
except KeyboardInterrupt:
    print('\nAudit interrupted by user.')