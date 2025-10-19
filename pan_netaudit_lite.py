# pan_netaudit_lite.py

import tkinter as tk
from tkinter import filedialog, messagebox
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET 
# Import the checks module and the new function
try:
    from pan_compliance_checks import run_all_checks_panos, NS, get_total_checks
except ImportError:
    messagebox.showerror("Error", "Could not import 'pan_compliance_checks.py'. Make sure it is in the same directory.")
    exit()

# Setup Jinja2 environment to load the HTML template
env = Environment(loader=FileSystemLoader('.'))
template = env.get_template('report_template.html')

# --- FINAL ROBUST FUNCTION TO FIND THE XML START AND STRIP BOM ---
def clean_xml_file(file_path):
    """
    Reads the file using 'utf-8-sig' to strip the BOM, finds the first '<', 
    and returns the cleaned XML content.
    """
    try:
        with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            content = f.read()
            
        xml_start_index = content.find('<')
        
        if xml_start_index == -1:
            raise ValueError("File appears empty or corrupted (no XML tag found).")
            
        cleaned_content = content[xml_start_index:].lstrip()
        
        if not cleaned_content.startswith('<'):
            raise ValueError("Cleaning failed to result in valid XML start.")
            
        return cleaned_content
        
    except ET.ParseError as pe:
        raise pe
    except Exception as e:
        raise Exception(f"Failed to read or locate XML start: {e}")


class PanNetAuditLite(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PAN-OS Audit Lite - XML Configuration Review Tool")
        self.geometry("600x400")
        self.config_file_path = None

        self.create_widgets()

    def create_widgets(self):
        # 1. Title Label
        title_label = tk.Label(self, text="Palo Alto XML Configuration Audit Tool", font=("Arial", 16, "bold"), fg="#004d99")
        title_label.pack(pady=20)

        # 2. File Selection Frame
        file_frame = tk.Frame(self)
        file_frame.pack(pady=10)

        self.path_label = tk.Label(file_frame, text="No file selected.", width=40, anchor="w")
        self.path_label.pack(side=tk.LEFT, padx=10)

        file_button = tk.Button(file_frame, text="Select XML Config File", command=self.select_config_file, bg="#4CAF50", fg="white")
        file_button.pack(side=tk.LEFT)
        
        # 3. Instruction Label (to guide the user)
        instr_label = tk.Label(self, text="Upload a Palo Alto 'export configuration' file (XML format).", fg="#666")
        instr_label.pack(pady=5)

        # 4. Run Audit Button
        audit_button = tk.Button(self, text="RUN XML CONFIGURATION AUDIT", command=self.run_audit, font=("Arial", 12, "bold"), bg="#004d99", fg="white", height=2)
        audit_button.pack(pady=30, padx=50, fill=tk.X)

        # 5. Status Message Area
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self, textvariable=self.status_var, fg="red")
        self.status_label.pack(pady=10)

    def select_config_file(self):
        """Opens a dialog to select the configuration file."""
        file_path = filedialog.askopenfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if file_path:
            self.config_file_path = file_path
            self.path_label.config(text=os.path.basename(file_path))
            self.status_var.set(f"File loaded: {os.path.basename(file_path)}")

    def run_audit(self):
        """Reads XML config, runs checks, and generates HTML report."""
        if not self.config_file_path or not os.path.exists(self.config_file_path):
            self.status_var.set("Please select a valid XML configuration file first.")
            messagebox.showerror("Error", "Please select a valid XML configuration file first.")
            return

        try:
            self.status_var.set("Cleaning and parsing XML file...")
            self.update() 

            # 1. Clean and Parse XML Configuration File
            clean_xml_content = clean_xml_file(self.config_file_path)
            xml_root = ET.fromstring(clean_xml_content)

            # 2. Run Checks
            # Use the new, robust function to get the total number of checks
            total_possible_checks = get_total_checks()
            
            self.status_var.set("Running compliance checks...")
            self.update() 
            findings = run_all_checks_panos(xml_root)
            
            # 3. Calculate Chart Data
            fail_count = sum(1 for f in findings if f.status == "Fail")
            manual_count = sum(1 for f in findings if f.status == "Manual")
            # Calculate passes by subtracting fails/manuals from the total number of defined checks
            pass_count = max(0, total_possible_checks - fail_count - manual_count) 

            status_counts = {"Fail": fail_count, "Manual": manual_count, "Pass": pass_count}
            
            risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for finding in findings:
                risk_counts[finding.risk] += 1
            
            # Format data for Jinja2 
            report_data = {
                "filename": os.path.basename(self.config_file_path),
                "review_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "findings": findings,
                "status_counts": status_counts,
                "risk_counts": risk_counts
            }

            # 4. Render HTML Report
            html_output = template.render(report_data)

            # 5. Save Report - Use UTF-8 encoding
            report_filename = f"PAN_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_output)
            
            self.status_var.set(f"Audit complete! Report saved as: {report_filename}")
            messagebox.showinfo("Success", f"PAN-OS audit complete! Report saved as:\n{report_filename}")

        except ValueError as ve:
            self.status_var.set(f"❌ File Content Error: {ve}")
            messagebox.showerror("Content Error", str(ve))
        except ET.ParseError as pe:
            self.status_var.set(f"❌ XML Parsing Error (Check file structure!): {pe}")
            messagebox.showerror("XML Error", f"The file is not valid XML even after robust cleaning. Error: {pe}")
        except Exception as e:
            self.status_var.set(f"❌ An unexpected error occurred: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred during audit: {e}")

if __name__ == "__main__":
    app = PanNetAuditLite()
    app.mainloop()