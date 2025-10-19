# pan_netaudit_lite.py

import tkinter as tk
from tkinter import filedialog, messagebox
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET 
from pan_compliance_checks import run_all_checks_panos

# Setup Jinja2 environment to load the HTML template
env = Environment(loader=FileSystemLoader('.'))
template = env.get_template('report_template.html')


# --- CLEAN XML AND REMOVE BOM / PREAMBLE ---
def clean_xml_file(file_path):
    """
    Cleans Palo Alto XML configuration files by removing BOM and trimming
    any non-XML data before the <config> root element.
    """
    try:
        with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            content = f.read()

        # Locate the <config> tag which is the XML root
        start_index = content.find('<config')
        if start_index == -1:
            raise ValueError("Could not find <config> root element in file. File may be invalid or not a PAN-OS export.")

        cleaned = content[start_index:].strip()
        return cleaned

    except Exception as e:
        raise Exception(f"Failed to clean XML file: {e}")


# --- EXTRACT DYNAMIC NAMESPACE ---
def extract_namespace(xml_root):
    """
    Extracts the namespace URI from the root element (if it exists).
    """
    if xml_root.tag.startswith("{"):
        uri = xml_root.tag.split("}")[0].strip("{")
        return {'ns': uri}
    else:
        return {'ns': ''}


class PanNetAuditLite(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PAN-OS Audit Lite - XML Configuration Review Tool")
        self.geometry("600x400")
        self.config_file_path = None
        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(self, text="Palo Alto XML Configuration Audit Tool",
                               font=("Arial", 16, "bold"), fg="#004d99")
        title_label.pack(pady=20)

        file_frame = tk.Frame(self)
        file_frame.pack(pady=10)

        self.path_label = tk.Label(file_frame, text="No file selected.", width=40, anchor="w")
        self.path_label.pack(side=tk.LEFT, padx=10)

        file_button = tk.Button(file_frame, text="Select XML Config File",
                                command=self.select_config_file, bg="#4CAF50", fg="white")
        file_button.pack(side=tk.LEFT)

        instr_label = tk.Label(self, text="Upload a Palo Alto 'export configuration' file (XML format).", fg="#666")
        instr_label.pack(pady=5)

        audit_button = tk.Button(self, text="RUN XML CONFIGURATION AUDIT",
                                 command=self.run_audit, font=("Arial", 12, "bold"),
                                 bg="#004d99", fg="white", height=2)
        audit_button.pack(pady=30, padx=50, fill=tk.X)

        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self, textvariable=self.status_var, fg="red")
        self.status_label.pack(pady=10)

    def select_config_file(self):
        """Open a file dialog to select the XML configuration file."""
        file_path = filedialog.askopenfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if file_path:
            self.config_file_path = file_path
            self.path_label.config(text=os.path.basename(file_path))
            self.status_var.set(f"File loaded: {os.path.basename(file_path)}")

    def run_audit(self):
        """Runs the configuration audit and generates an HTML report."""
        if not self.config_file_path or not os.path.exists(self.config_file_path):
            self.status_var.set("Please select a valid XML configuration file first.")
            messagebox.showerror("Error", "Please select a valid XML configuration file first.")
            return

        try:
            self.status_var.set("Cleaning and parsing XML file...")
            self.update()

            # Step 1: Clean and Parse XML
            clean_xml_content = clean_xml_file(self.config_file_path)
            xml_root = ET.fromstring(clean_xml_content)

            # Step 2: Extract Namespace dynamically
            NS = extract_namespace(xml_root)

            # Step 3: Prepare dummy XML for total check calculation
            namespace_uri = list(NS.values())[0]
            dummy_xml = f'<config xmlns="{namespace_uri}"></config>'
            dummy_root = ET.fromstring(dummy_xml)

            total_possible_checks = len(run_all_checks_panos(dummy_root, NS))

            self.status_var.set("Running compliance checks...")
            self.update()

            findings = run_all_checks_panos(xml_root, NS)

            # Step 4: Aggregate results
            fail_count = sum(1 for f in findings if f.status == "Fail")
            manual_count = sum(1 for f in findings if f.status == "Manual")
            pass_count = max(0, total_possible_checks - fail_count - manual_count)

            status_counts = {"Fail": fail_count, "Manual": manual_count, "Pass": pass_count}
            risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

            for finding in findings:
                if finding.risk in risk_counts:
                    risk_counts[finding.risk] += 1

            report_data = {
                "filename": os.path.basename(self.config_file_path),
                "review_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "findings": findings,
                "status_counts": status_counts,
                "risk_counts": risk_counts
            }

            # Step 5: Render and Save HTML Report
            html_output = template.render(report_data)
            report_filename = f"PAN_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_output)

            self.status_var.set(f"Audit complete! Report saved as: {report_filename}")
            messagebox.showinfo("Success", f"PAN-OS audit complete! Report saved as:\n{report_filename}")

        except ValueError as ve:
            self.status_var.set(f"❌ File Content Error: {ve}")
            messagebox.showerror("Content Error", str(ve))
        except ET.ParseError as pe:
            self.status_var.set(f"❌ XML Parsing Error: {pe}")
            messagebox.showerror("XML Error", f"Invalid XML structure. Verify the XML export. Error: {pe}")
        except Exception as e:
            self.status_var.set(f"❌ Unexpected error: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    app = PanNetAuditLite()
    app.mainloop()
