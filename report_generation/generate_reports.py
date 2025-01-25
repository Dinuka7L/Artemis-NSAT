
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfgen import canvas
from datetime import datetime
from PyPDF2 import PdfReader, PdfWriter, PageObject, PdfMerger
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
import io
import matplotlib.pyplot as plt

from colorama import Fore, Back, Style, init
# Initialize colorama
init(autoreset=True)

def add_header(input_file, output_file, page_size, image_path=None):
    """
    Adds a header to an existing PDF file with an image at the top-right corner.
    
    Args:
        input_file (str): Path to the existing PDF file.
        output_file (str): Path where the new PDF will be saved.
        page_size (str): Page size to be used ('letter' or 'landscape').
        image_path (str): Path to the PNG image to be added to the top-right corner.
    """
    if not image_path:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No image path provided. Skipping image addition.")
        return

    if page_size == "letter":
        page_size = letter
    elif page_size == "landscape":
        page_size = landscape(letter)
    else:
        raise ValueError(Style.BRIGHT + Fore.LIGHTRED_EX + "Unsupported page size. Use 'letter' or 'landscape'.")

    with open(input_file, "rb") as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            packet = io.BytesIO()

            c = canvas.Canvas(packet, pagesize=page_size)
            if page_size == letter:
                c.drawImage(image_path, 480, 720, width=100, height=80)
            elif page_size == landscape(letter):
                c.drawImage(image_path, 640, 540, width=120, height=100)
            
            c.save()  # Save canvas before using it

            packet.seek(0)
            overlay_pdf = PdfReader(packet)

            if len(overlay_pdf.pages) == 0:
                raise ValueError(Style.BRIGHT + Fore.LIGHTRED_EX + "The overlay PDF generated from the canvas is empty.")

            new_page = PageObject.create_blank_page(width=page_size[0], height=page_size[1])
            new_page.merge_page(overlay_pdf.pages[0])
            new_page.merge_page(page)
            writer.add_page(new_page)

        with open(output_file, "wb") as output:
            writer.write(output)

    print(Style.BRIGHT + Fore.BLUE + f"PDF saved to {output_file}")



def create_gauge_chart(score):
    # Gauge chart colors and values
    colors_list = ['#4dab6d', "#72c66e", "#c1da64", "#f6ee54", "#fabd57", "#f36d54", "#ee4d55"]
    values = [100, 80, 60, 40, 20, 0, -20]
    x_axis_vals = [0, 0.44, 0.88, 1.32, 1.76, 2.2, 2.64]

    # Increase figure size for a larger gauge
    fig = plt.figure(figsize=(8, 8))  # Adjusted from (6, 6) to (8, 8)
    ax = fig.add_subplot(projection="polar")
    
    # Create the gauge segments
    ax.bar(x_axis_vals, [0.5] * len(x_axis_vals), width=0.5, bottom=2, linewidth=3, edgecolor="white",
           color=colors_list, align="edge")
    
   
    # Add compliance score pointer
    if score == 0.00:
        angle = ((score / 100) + (3.14 / 2)) *2
    else:
        angle = (1 - (score / 100)) * 3.14  # Scale score to polar coordinates
    plt.annotate(str(score), xytext=(0, 0), xy=(angle, 2.35),  # Adjusted position for better alignment
                 arrowprops=dict(arrowstyle="wedge, tail_width=0.5", color="black", shrinkA=0),
                 bbox=dict(boxstyle="circle", facecolor="black", linewidth=2.0),
                 fontsize=15, color="white", ha="center")  # Increased font size
    
    # Remove axes and set title
    ax.set_axis_off()
    plt.title("Overall Compliance Score Guage", loc="center", pad=30, fontsize=18, fontweight="bold")  # Increased padding and font size

    # Save the chart to a buffer
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf






from PyPDF2 import PdfReader, PdfWriter, PageObject
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
import io

def add_footer(input_file, output_file, page_size="letter", text="ARTEMIS"):
    """
    Adds a footer to an existing PDF file.
    - Adds page number to the bottom-right and the text to the bottom-left (footer).
    
    Args:
        input_file (str): Path to the existing PDF file.
        output_file (str): Path where the new PDF will be saved.
        page_size (str): Page size to be used ('letter' or 'landscape').
        text (str): Text to display in the bottom-left corner of the footer.
    """
    # Determine page size
    if page_size == "letter":
        page_size = letter
    elif page_size == "landscape":
        page_size = landscape(letter)
    else:
        raise ValueError(Style.BRIGHT + Fore.LIGHTRED_EX + "Unsupported page size. Use 'letter' or 'landscape'.")

    with open(input_file, "rb") as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]

            # Create a new buffer for the canvas
            packet = io.BytesIO()
            c = canvas.Canvas(packet, pagesize=page_size)
            
            # Draw footer text and page number
            c.drawString(20, 20, text)
            c.drawString(page_size[0] - 70, 20, f"Page {page_num + 1}")  # Adjust for right alignment
            c.save()

            # Create a new page for the footer overlay
            packet.seek(0)
            overlay_pdf = PdfReader(packet)
            overlay_page = overlay_pdf.pages[0]

            # Create a new blank page object matching the desired page size
            new_page = PageObject.create_blank_page(width=page_size[0], height=page_size[1])

            # Merge the footer overlay and original content
            new_page.merge_page(overlay_page)
            new_page.merge_page(page)

            # Add the final modified page to the writer
            writer.add_page(new_page)

        with open(output_file, "wb") as output:
            writer.write(output)

    print(Style.BRIGHT + Fore.BLUE + f"PDF saved to {output_file}")

def generate_port_security_status_dict(port_security_status):
    # Function to format the port security status into a human-readable string
    formatted_data = {}
    for interface, details in port_security_status.items():
        formatted_data[interface] = {
            "Port Security Enabled": details.get("Port Security Enabled", "N/A"),
            "Port Status": details.get("Port Status", "N/A"),
            "Max MAC Addresses": details.get("Max MAC Addresses", "N/A"),
            "Current MAC Addresses": details.get("Current MAC Addresses", "N/A"),
            "Violation Mode": details.get("Violation Mode", "N/A"),
            "Violation Count": details.get("Violation Count", "N/A"),
            "Aging Time": details.get("Aging Time", "N/A"),
        }
    return formatted_data



import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfgen import canvas
from datetime import datetime
from PyPDF2 import PdfReader, PdfWriter, PageObject
import io

def write_to_file(input_file, output_file, page_sizes):
    """
    Writes content from the input PDF to a new file, supporting a mix of page sizes.

    Args:
        input_file (str): Path to the input PDF file.
        output_file (str): Path to the output PDF file.
        page_sizes (list): List of page sizes corresponding to each page in the input PDF.
                           Use 'letter' or 'landscape' as valid sizes.
    """
    with open(input_file, "rb") as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        for page_num, size in enumerate(page_sizes):
            page = reader.pages[page_num]
            if size == "letter":
                page_size = letter
            elif size == "landscape":
                page_size = landscape(letter)
            else:
                raise ValueError(Style.BRIGHT + Fore.LIGHTRED_EX + "Unsupported page size. Use 'letter' or 'landscape'.")

            new_page = PageObject.create_blank_page(width=page_size[0], height=page_size[1])
            new_page.merge_page(page)
            writer.add_page(new_page)

        with open(output_file, "wb") as output:
            writer.write(output)

    print(Style.BRIGHT + f"PDF written to {output_file}")


def generate_main_page():
    """
    Generates a cover page for the report with a logo and main title.
    """
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)

    c.setFont("Helvetica-Bold", 36)
    c.drawString(150, 500, "ARTEMIS")

    c.setFont("Helvetica-Bold", 24)
    c.drawString(100, 450, "Network Security Posture Report")

    c.setFont("Helvetica", 14)
    c.drawString(100, 400, f"Report Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.save()
    packet.seek(0)
    return packet

def generate_cisco_ios_version(ios_version):
    return f"Cisco IOS Version: {ios_version}"

def generate_telnet_status(enabled):
    status = "Enabled" if enabled else "Disabled"
    return f"Telnet Status: {status}"

def generate_ssh_version_status(version):
    return f"SSH Version Status: {version}"

def generate_password_encryption(enabled):
    status = "Enabled" if enabled else "Disabled"
    return f"Password Encryption Status: {status}"

def generate_enable_secret(secret_hash):
    return f"Enable Secret: {secret_hash}"

def generate_enable_motd(motd):
    return f"Enabled MOTD: {motd}"

def generate_syslog(server_ip):
    return f"Logging Server: {server_ip}"

def generate_exec_timeout(timeout_minutes):
    return f"Remote Login Exec Timeout: {timeout_minutes}"

def generate_cisco_ios_version(ios_version):
    return f"Cisco IOS Version: {ios_version}"

def generate_banner_motd(motd):
    return f"Banner MOTD: {motd}"

def generate_syslog(server_ip):
    return f"Logging Server: {server_ip}"

def generate_exec_timeout(timeout_minutes):
    return f"Remote Login Exec Timeout: {timeout_minutes}"

def generate_bpdu_guard_status(bpdu_guard_status):
    return f"BPDU Guard Status: {bpdu_guard_status}"

def generate_root_guard_status(root_guard_status):  
    return f"Root Guard Status: {root_guard_status}"

def generate_unused_ports_status(unused_ports_status):
    return f"Unused Ports Status: {unused_ports_status}"

def generate_active_ports_status(active_ports_status):
    return f"Active Ports Status: {active_ports_status}"

def generate_disable_dtp_status(disable_dtp_status):
    return f"Disable DTP Status: {disable_dtp_status}"

def generate_disable_cdp_status(disable_cdp_status):
    return f"Disable CDP Status: {disable_cdp_status}"

def generate_dhcp_snooping_status(dhcp_snooping_status):
    return f"DHCP Snooping Status: {dhcp_snooping_status}"

def generate_dynamic_arp_inspection_status(dynamic_arp_inspection_status):  
    return f"Dynamic ARP Inspection Status: {dynamic_arp_inspection_status}"

def generate_login_fail_lockdown_status(login_fail_lockdown_status):
    return f"Login Fail Lockdown Status: {login_fail_lockdown_status}"


def merge_reports(temp_files, output_file):
    """
    Merges multiple PDF files into a single output file.
    
    Args:
        temp_files (list): List of temporary PDF file paths to merge.
        output_file (str): Output path for the merged PDF.
    """
    merger = PdfMerger()
    for file in temp_files:
        merger.append(file)
    merger.write(output_file)
    merger.close()



import ast
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime

def create_pdf_report(report_data, pdf_output_path):
    """
    Create a PDF report from the provided report data, displaying information in a structured format.
    Interfaces and controls are displayed as bulleted points, and each device report begins on a new page.
    """
    elements = []
    styles = getSampleStyleSheet()

    # Title
    title = Paragraph("<h1>Network Security Posture Report</h1>", styles['Title'])
    elements.append(title)

    subtitle = Paragraph("<b>This report contains the security posture for selected devices:</b>", styles['Normal'])
    elements.append(subtitle)
    elements.append(Spacer(1, 12))

    for device_report in report_data:
        device_info = (f"<h2>Device Information</h2><br/>"
                f"<b>Device Name:</b> {device_report['name']}<br/>"
                f"<b>IP:</b> {device_report['ip']}<br/>"
                f"<b>IOS Version:</b> {device_report.get('ios_version', 'Unknown')}<br/>"
                f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>")


        elements.append(Paragraph(device_info, styles['Normal']))
        elements.append(Spacer(1, 12))

        # Display control results as bulleted points
        if device_report['results']:
            elements.append(Paragraph("<b>Control Results:</b>", styles['Heading3']))
            for control_id, result in device_report['results'].items():
                print("Control ID", control_id)
                if control_id in ['10', '11', '12', '13', '14', '15', '16', '17']:
                    try:
                        # Extract only the dictionary part of the result (after ": ")
                        result = result.split(": ")[-1]
                        
                        # Replace single quotes with double quotes to handle formatting correctly
                        result = result.replace("'", "\"")  # JSON-style dictionary formatting
                        
                        # Convert the string to a dictionary
                        result_dict = ast.literal_eval(result)

                        # Add the heading for the Control
                        elements.append(Paragraph(f"<b>Control {control_id}:</b>", styles['Normal']))
                        
                        # Loop through the dictionary and display the interfaces as bullet points
                        if isinstance(result_dict, dict):
                            for interface, status in result_dict.items():
                                elements.append(Paragraph(f"&bull; {interface}: {status}", styles['Normal']))
                    except Exception as e:
                        # If there's an error parsing, log it
                        print(f"Error processing Control {control_id}: {e}")

                if control_id !='9': 
                    if isinstance(result, dict):
                        elements.append(Paragraph(f"<b>Control {control_id}:</b>", styles['Normal']))
                        for key, value in result.items():
                            elements.append(Paragraph(f"&bull; {key}: {value}", styles['Normal']))
                    else:
                        elements.append(Paragraph(f"&bull; Control {control_id}: {result}", styles['Normal']))
                elements.append(Spacer(1, 12))

        # Handle port security data with compact cell spacing
        if '9' in device_report['results'] and isinstance(device_report['results']['9'], dict):
            port_security_status = device_report['results']['9']
            port_security_data = [["Interface", "Port Security Enabled", "Port Status", "Max MAC Addresses",
                                   "Current MAC Addresses", "Violation Mode", "Violation Count", "Aging Time"]]
            for interface, details in port_security_status.items():
                row = [interface] + list(details.values())
                port_security_data.append(row)

            port_security_table = Table(port_security_data, colWidths=[70] + [60] * 7)
            port_security_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8)]))
            elements.append(Paragraph("<b>Port Security Status:</b>", styles['Heading3']))
            elements.append(port_security_table)
            elements.append(Spacer(1, 12))

        elements.append(PageBreak())

    doc = SimpleDocTemplate(pdf_output_path, pagesize=letter)
    doc.build(elements)
    print(f"PDF report saved to {pdf_output_path}")



styles = getSampleStyleSheet()


def generate_device_report_pdf(device_reports, overview, output_file):
    elements = []

    # Title Page with Compliance Overview
    title = Paragraph("<h1>Device Compliance Report</h1>", styles['Title'])
    elements.append(title)

    subtitle = Paragraph("<b>Device Security Compliance Overview and General Summary</b>", styles['Normal'])
    elements.append(subtitle)
    device_info = Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>", styles['Normal'])
    elements.append(device_info)
    elements.append(Spacer(1, 12))


    # Overview Section
    elements.append(Paragraph("<h2>Compliance Overview</h2>", styles['Heading2']))
    for item in overview:
        if "Overall Security Compliance Score:" in item:
            score = float(item.split(':')[1].strip().strip('%'))
            gauge_buf = create_gauge_chart(score)  # Create the gauge chart
            elements.append(Image(gauge_buf, width=250, height=250))  # Embed the chart in the PDF
            break
    bullet_items = []
    overview = [item.strip() for item in overview if 'Compliance' in item]
    overview = [item.strip() for item in overview if '-' not in item]
    
    for item in overview:
        clean_item = item.replace('\n', '').strip()
        if clean_item.startswith("Overall Security Compliance Score:"):
            score = float(clean_item.split(':')[1].strip('%'))
            if score < 20:
                color = "red"
            elif 20 <= score <= 40:
                color = "maroon"    
            elif 40 <= score <= 60:
                color = "orange"
            elif 60 <= score <= 80:
                color = "olive"
            else:
                color = "lime"
            formatted_score = f"<font color='{color}'>{clean_item}</font>"
            bullet_items.append(ListItem(Paragraph(formatted_score, styles['Normal']), bulletColor=colors.black))
        else:
            bullet_items.append(ListItem(Paragraph(clean_item, styles['Normal']), bulletColor=colors.black))

    elements.append(ListFlowable(bullet_items, bulletType='bullet'))
    elements.append(Spacer(1, 24))

    # Network Vulnerabilities Section
    elements.append(Paragraph("<h2>Network Vulnerabilities</h2>", styles['Heading2']))
    if device_reports:
        vulnerabilities_list = []
        for device in device_reports:
            device_name = device.get('name', 'Unknown Device')
            vulnerabilities = device.get('vulnerabilities', [])
            if vulnerabilities:
                elements.append(Paragraph(f"<b>Device:</b> {device_name}", styles['Normal']))
                vul_items = [ListItem(Paragraph(vuln, styles['Normal']), bulletColor=colors.red) for vuln in vulnerabilities]
                vulnerabilities_list.extend(vul_items)
                elements.append(ListFlowable(vul_items, bulletType='bullet'))
                elements.append(Spacer(1, 12))
    else:
        elements.append(Paragraph("<i>No vulnerabilities detected across devices.</i>", styles['Normal']))


    # Device Details: Each device starts on a new page
    for device in device_reports:
        elements.append(PageBreak())

        # Device Information
        device_info = (f"<h2>Device Information</h2><br/>"
                       f"<b>Device Name:</b> {device['name']}<br/>"
                       f"<b>IP Address:</b> {device['ip']}<br/>"
                       f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>")

        elements.append(Paragraph(device_info, styles['Normal']))
        elements.append(Spacer(1, 6))

        # General Results Section
        results_data = [(key, value) for key, value in device['results'].items() if not isinstance(value, dict)]
        if results_data:
            results_table = Table(results_data, colWidths=[200, 300])
            results_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT')
            ]))
            elements.append(Paragraph("<b>General Results</b>", styles['Heading3']))
            elements.append(results_table)
            elements.append(Spacer(1, 12))

        # Compliance Summary Section
        for key, value in device['results'].items():
            if isinstance(value, dict):
                compliance_summary = [(f"{k}:", str(v)) for k, v in value.items() if k not in 
                                      ['Unsecured Ports', 'Disabled Ports', 'Enabled Ports', 'Trusted Ports', 'Untrusted Ports']]
                compliance_table = Table(compliance_summary, colWidths=[180, 300])
                compliance_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                ]))
                elements.append(Paragraph(f"<b>{key}</b>", styles['Heading3']))
                elements.append(compliance_table)
                elements.append(Spacer(1, 6))

                for ports_key in ['Unsecured Ports', 'Disabled Ports', 'Enabled Ports', 'Trusted Ports', 'Untrusted Ports']:
                    if ports_key in value and value[ports_key]:
                        elements.append(Paragraph(f"<b>{ports_key}</b>", styles['Heading4']))
                        bullet_items = [ListItem(Paragraph(port, styles['Normal']), bulletColor=colors.black) for port in value[ports_key]]
                        elements.append(ListFlowable(bullet_items, bulletType='bullet'))
                        elements.append(Spacer(1, 6))

    # Generate PDF document
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    doc.build(elements)
