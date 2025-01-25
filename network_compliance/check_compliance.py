import sys
import os
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Back, Style, init


# Initialize colorama
init(autoreset=True)

# Add the current script's directory to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Add all subdirectories of the parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
for root, dirs, files in os.walk(parent_dir):
    sys.path.append(root)


from device_config import cisco_ios_get
from connection_management.encrypted_connections import get_device_credentials
from connection_management.encrypted_connections import list_devices
import report_generation.generate_reports  

def get_multiple_device_selection():
    """
    Prompts the user to select one or more devices from a list and returns the selected
    devices as a list of dictionaries with their details.

    Returns:
        list: A list of dictionaries containing device connection details.
    """
    devices = list_devices()
    if not devices:
        print("No devices available.")
        exit()

    print("Available devices:")
    for i, device in enumerate(devices, 1):
        print(f"{i}. {device['devicename']} (IP: {device['ip']})")

    choices = input("Select device numbers separated by commas (e.g., 1,3,5): ").strip().split(',')
    selected_devices = []

    for choice in choices:
        try:
            index = int(choice) - 1
            if index < 0 or index >= len(devices):
                print(f"Invalid choice: {choice}. Skipping.")
                continue

            selected_device = devices[index]
            target_ip = selected_device["ip"]
            credentials = get_device_credentials(target_ip)

            if not credentials:
                print(f"No credentials found for {target_ip}. Skipping.")
                continue

            device_entry = {
                "device_category": selected_device["device_category"],
                "device_name": selected_device["devicename"],
                "device_type": "cisco_ios",
                "host": target_ip,
                "username": credentials[0]["username"],
                "password": credentials[0]["password"],
                "secret": credentials[0]["enable_secret"],
            }
            selected_devices.append(device_entry)

        except ValueError:
            print(f"Invalid input: {choice}. Skipping.")

    if not selected_devices:
        print("No valid devices were selected.")
        exit()

    return selected_devices


def selective_controls():
    """
    Prompts the user to select controls for a list of devices, checks the selected
    configurations, and generates a compliance report.
    """
    # Step 1: Get selected devices
    selected_devices = get_multiple_device_selection()

    # Step 2: Display available controls for selection
    device_controls = {
        "router": ["1. Telnet Disabled", "2. SSH V2 Enabled", "3. Password Encryption",
                   "4. Privilege Exec Password",
                   "5. Enable MOTD", "6. Syslog", "7. Exec Timeout"],
        "switch": ["1. Telnet Disabled", "2. SSH V2 Enabled", "3. Password Encryption",
                   "4. Privilege Exec Password",
                   "5. Enable MOTD", "6. Syslog", "7. Exec Timeout",
                   "8. Port Security on Interfaces", "9. BPDU Guard", "10. Root Guard",
                   "11. Disable DTP", "12. Disable CDP", "13. DHCP Snooping", 
                   "14. Dynamic ARP Inspection", "15. Login Fail Lock"],
    }

    control_weights = {
        "Telnet Disabled": 5, "SSH V2 Enabled": 5, "Password Encryption": 10,
        "Privilege Exec Password": 10, "Enable MOTD": 3,
        "Syslog": 5, "Exec Timeout": 5, "Port Security on Interfaces": 15,
        "BPDU Guard": 5, "Root Guard": 5, "Disable DTP": 5, "Disable CDP": 5,
          "DHCP Snooping": 10, "Dynamic ARP Inspection": 10, "Login Fail Lock": 7,
    }

    category_scores = defaultdict(lambda: {"score": 0, "weight": 0})
    overall_compliance_score = 0
    device_reports = []

    for device in selected_devices:
        print(f"Processing device: {device['device_name']} (IP: {device['host']})")
        device_type = device["device_category"].lower()
        available_controls = device_controls.get(device_type, [])

        if not available_controls:
            print(f"No controls available for {device_type}. Skipping device.")
            continue

        print("Available controls:")
        for control in available_controls:
            print(control)

        control_selection = input(f"Select controls for {device['device_name']} (e.g., 1,3,5): ").split(',')

        device_report = {"name": device["device_name"], "ip": device["host"], "results": {}}
        device_details_formatted = device.copy()
        del device_details_formatted['device_category']
        del device_details_formatted['device_name']
        failed_vulnerabilities = []
        for selected_option in control_selection:
            selected_option = selected_option.strip()
            result = ""
            fail_conditions = []

            if selected_option == "1":
                result = cisco_ios_get.is_telnet_enabled(device_details_formatted)
                fail_conditions = ["telnet access is enabled"]
            elif selected_option == "2":
                result = cisco_ios_get.is_ssh_enabled(device_details_formatted)
                fail_conditions = ["SSH version 2 is not enabled."]
            elif selected_option == "3":
                result = cisco_ios_get.check_password_encryption(device_details_formatted)
                fail_conditions = ["Password encryption is explicitly disabled.", "Authentication to device failed", "TCP connection to device failed"]
            elif selected_option == "4":
                result = cisco_ios_get.check_privilege_exec_password(device_details_formatted)
                fail_conditions = ["Enable secret is not configured."]
            elif selected_option == "5":
                result = cisco_ios_get.check_enable_motd(device_details_formatted)
                fail_conditions = ["MOTD banner not configured."]
            elif selected_option == "6":
                result = cisco_ios_get.check_syslog(device_details_formatted)
                fail_conditions = ["No remote logging enabled."]
            elif selected_option == "7":
                result = cisco_ios_get.check_exec_timeout(device_details_formatted)
                fail_conditions = ["Exec timeout not configured for line vty 0 4."]
            elif selected_option == "8":
                # Your original logic for option 8
                port_security_status = cisco_ios_get.check_port_security_all_interfaces(device_details_formatted)
                trunk_ports = cisco_ios_get.get_trunk_ports(device_details_formatted)
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                
                if isinstance(trunk_ports, dict) and "Error" in trunk_ports:
                    print(f"Error retrieving trunk ports: {trunk_ports['Error']}")
                    return {"Compliance Score": "Error", "Unsecured Ports": []}
                
                access_ports = [port for port in all_interfaces if port not in trunk_ports]
                total_ports = len(access_ports)
                secure_ports = 0
                unsecured_ports = []

                for interface in access_ports:
                    if interface in port_security_status and port_security_status[interface]['Port Security Enabled'] == 'Enabled':
                        secure_ports += 1
                    elif interface in port_security_status:
                        unsecured_ports.append(interface)

                if total_ports > 0:
                    security_enabled_percentage = (secure_ports / total_ports) * 100
                    compliance_score = security_enabled_percentage  # Adjust as needed
                else:
                    security_enabled_percentage = 0
                    compliance_score = 0

                result = {
                    "Compliance Score": f"{compliance_score:.2f}%",
                    "Secure Ports Percentage": f"{security_enabled_percentage:.2f}%",
                    "Unsecured Ports": unsecured_ports
                }
            elif selected_option == "9":
                """
                Calculate BPDU Guard compliance, excluding trunk ports.
                :param device: Device connection details.
                :param bpdu_guard_status: Dictionary with BPDU Guard status for interfaces.
                :param all_interfaces: List of all interfaces on the device.
                :return: Dictionary with BPDU Guard compliance report.
                """
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                bpdu_guard_status = cisco_ios_get.check_bpdu_guard(device_details_formatted)
                trunk_ports = cisco_ios_get.get_trunk_ports(device_details_formatted)

                if isinstance(all_interfaces, dict) and "Error" in all_interfaces:
                    print(f"Error retrieving interfaces: {all_interfaces['Error']}")
                    device_report["results"]["BPDU Guard"] = "Error"
                elif "Error" in bpdu_guard_status:
                    print(f"Error: {bpdu_guard_status['Error']}")
                    device_report["results"]["BPDU Guard"] = "Error"
                elif isinstance(trunk_ports, dict) and "Error" in trunk_ports:
                    print(f"Error retrieving trunk ports: {trunk_ports['Error']}")
                    device_report["results"]["BPDU Guard"] = "Error"
                else:
                    # Exclude trunk ports from the total port count
                    non_trunk_ports = [port for port in all_interfaces if port not in trunk_ports]
                    total_ports = len(non_trunk_ports)
                    enabled_ports = len([port for port in non_trunk_ports if port in bpdu_guard_status and bpdu_guard_status[port] == 'Enabled'])
                    disabled_ports = [port for port in non_trunk_ports if port not in bpdu_guard_status or bpdu_guard_status[port] != 'Enabled']

                    # Calculate BPDU Guard compliance
                    if total_ports > 0:
                        compliance_score = (enabled_ports / total_ports) * 100
                    else:
                        compliance_score = 0

                    # Prepare the report with disabled ports and compliance score
                    result = { "Compliance Score": f"{compliance_score:.2f}%",
                        "Enabled Ports Percentage": f"{compliance_score:.2f}%",
                        "Disabled Ports": disabled_ports }
            elif selected_option == "10":
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                root_guard_status = cisco_ios_get.check_root_guard(device_details_formatted)
                
                #print("All interfaces:", all_interfaces)
                #print("Root Guard status:", root_guard_status)
                
                if isinstance(all_interfaces, dict) and "Error" in all_interfaces:
                    print(f"Error retrieving interfaces: {all_interfaces['Error']}")
                    device_report["results"]["Root Guard"] = "Error"
                elif "Error" in root_guard_status:
                    print(f"Error: {root_guard_status['Error']}")
                    device_report["results"]["Root Guard"] = "Error"
                else:
                    total_ports = len(all_interfaces)
                    enabled_ports = len(root_guard_status)  # Only ports with Root Guard enabled are returned
                    disabled_ports = [interface for interface in all_interfaces if interface not in root_guard_status]

                    # Calculate Root Guard compliance
                    if total_ports > 0:
                        compliance_score = (enabled_ports / total_ports) * 100
                        #print(f"Root Guard Compliance: {compliance_score:.2f}%")
                    else:
                        compliance_score = 0

                    # Prepare the report with disabled ports and compliance score
                    result = { "Compliance Score": f"{compliance_score:.2f}%",
                        "Enabled Ports Percentage": f"{compliance_score:.2f}%",
                        "Disabled Ports": disabled_ports }
            elif selected_option == "11":
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                dtp_status = cisco_ios_get.check_disable_dtp(device_details_formatted)
                if isinstance(all_interfaces, dict) and "Error" in all_interfaces:
                    print(f"Error retrieving interfaces: {all_interfaces['Error']}")
                    device_report["results"]["DTP Compliance"] = "Error"
                elif "Error" in dtp_status:
                    print(f"Error: {dtp_status['Error']}")
                    device_report["results"]["DTP Compliance"] = "Error"
        
                else:
                    total_ports = len(all_interfaces)
                    enabled_ports = [interface for interface in all_interfaces if interface not in dtp_status]
                    # Calculate CDP compliance score
                    if total_ports > 0:
                        if len(enabled_ports) == total_ports:
                            compliance_score = 0  # Vulnerable if DTP is enabled on all access links
                        else:
                            compliance_score = ((total_ports - len(enabled_ports)) / total_ports) * 100
                    else:
                        compliance_score = 0
                    # Prepare the report with enabled ports and compliance score
                    result = {
                        "Compliance Score": f"{compliance_score:.2f}%",
                        "Enabled/Total ports": f"{len(enabled_ports)} / {total_ports}",
                        "Enabled Ports Percentage": f"{((len(enabled_ports) - total_ports) / total_ports) * 100:.2f}%" if total_ports > 0 else "0.00%",
                        "Enabled Ports": enabled_ports}                 
            elif selected_option == "12":
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                cdp_status = cisco_ios_get.check_disable_cdp(device_details_formatted)

                if isinstance(all_interfaces, dict) and "Error" in all_interfaces:
                    print(f"Error retrieving interfaces: {all_interfaces['Error']}")
                    device_report["results"]["CDP Compliance"] = "Error"
                elif "Error" in cdp_status:
                    print(f"Error: {cdp_status['Error']}")
                    device_report["results"]["CDP Compliance"] = "Error"
                else:
                    total_ports = len(all_interfaces)
                    enabled_ports = [interface for interface in all_interfaces if interface not in cdp_status]
                    disabled_ports = [interface for interface in all_interfaces if interface not in cdp_status]
                    # Calculate CDP compliance score
                    if total_ports > 0:
                        if len(enabled_ports) == total_ports:
                            compliance_score = 0  # Vulnerable if CDP is enabled on all access links
                        else:
                            compliance_score = ((total_ports - len(enabled_ports)) / total_ports) * 100
                    else:
                        compliance_score = 0

                    # Prepare the report with enabled ports and compliance score
                    result = {
                        "Compliance Score": f"{compliance_score:.2f}%",
                        "Enabled/Total ports": f"{len(enabled_ports)} / {total_ports}",
                        "Enabled Ports Percentage": f"{(len(enabled_ports) / total_ports) * 100:.2f}%" if total_ports > 0 else "0.00%",
                        "Enabled Ports": enabled_ports}     
            elif selected_option == "13":
                all_interfaces = cisco_ios_get.get_all_interfaces_on_device(device_details_formatted)
                dhcp_snooping_status = cisco_ios_get.check_dhcp_snooping(device_details_formatted)
                if isinstance(all_interfaces, dict) and "Error" in all_interfaces:
                    print(f"Error retrieving interfaces: {all_interfaces['Error']}")
                    device_report["results"]["DHCP Snooping Compliance"] = "Error"
                elif "Error" in dhcp_snooping_status:
                    print(f"Error: {dhcp_snooping_status['Error']}")
                    device_report["results"]["DHCP Snooping Compliance"] = "Error"
                else:
                    total_ports = len(all_interfaces)

                    trusted_ports = dhcp_snooping_status.get('Trusted Interfaces', {})
                    untrusted_ports = dhcp_snooping_status.get('Untrusted Interfaces', {})
                    snooping_enabled_ports = set(trusted_ports.keys()).union(untrusted_ports.keys())

                    disabled_ports = [interface for interface in all_interfaces if interface not in snooping_enabled_ports]

                    # Calculate DHCP Snooping compliance score
                    if total_ports > 0:
                        compliance_score = ((total_ports - len(disabled_ports)) / total_ports) * 100
                    else:
                        compliance_score = 0.0

                    # Prepare detailed results
                    result = {
                        "Compliance Score": f"{compliance_score:.2f}%",
                        "Enabled/Total Ports": f"{len(snooping_enabled_ports)} / {total_ports}",
                        "Disabled Ports Percentage": f"{(len(disabled_ports) / total_ports) * 100:.2f}%" if total_ports > 0 else "0.00%",
                        "Disabled Ports": disabled_ports,
                        "Trusted Ports": trusted_ports,
                        "Untrusted Ports": untrusted_ports
                    }
            elif selected_option == "15":
                result = cisco_ios_get.check_login_fail_lock(device_details_formatted)
                fail_conditions = ["Login block-for (fail lock) configuration not found."]
            else:
                print(f"Invalid option: {selected_option}")
                continue

            vulnerabilities = {
                "Dhcp-starvation attack": [8, 13, 14],  
                "MAC-address overflow attack": [ 8, 9, 11],     
                "Port-security attack": [10, 11, 15],
                "BPDU-attack": [9, 10],                
                "Arp-spoofing": [13, 14],             
                "Unauthorized-login": [1, 2, 5, 7, 15],        
                "Dtp-attack": [11],                   
                "Cdp-information-leak": [12],
                "Credential theft": [3],
                "No system logs": [6] 
                        
            }   

            # Variable to store failed control vulnerabilities
            control_name = available_controls[int(selected_option) - 1].split('. ')[1]
            control_weight = control_weights.get(control_name, 0)
            category_scores[control_name]["weight"] += control_weight

            if isinstance(result, dict):
                compliance_score = float(result.get("Compliance Score", "0%").strip('%'))
                category_scores[control_name]["score"] += compliance_score * control_weight / 100
                control_index = int(selected_option)
                if compliance_score != 100.00:
                    for vulnerability, controls in vulnerabilities.items():
                        if control_index in controls:
                            failed_vulnerabilities.append(vulnerability)
                # Store the result in device report
                device_report["results"][control_name] = result
                
            elif isinstance(result, list):  # Handle list result formatting
                formatted_list = "".join(f"      - Server: {item}" for item in result)
                device_report["results"][control_name] = f":\n{formatted_list}"
            elif isinstance(result, str):
                result_lower = result.lower().strip()  # Normalize the result for matching
                if "authentication to device failed" in result_lower:
                    device_report["results"][control_name] = "Failed to authenticate connection with device"
                elif "tcp connection to device failed" in result_lower:
                    device_report["results"][control_name] = "Failed to establish connection with device"
                elif any(fail_condition.lower() in result_lower for fail_condition in fail_conditions):
                    device_report["results"][control_name] = "Fail"
                    # Append related vulnerabilities when a control fails
                    control_index = int(selected_option)
                    for vulnerability, controls in vulnerabilities.items():
                        if control_index in controls:
                            failed_vulnerabilities.append(vulnerability)
                else:
                    device_report["results"][control_name] = "Pass"
                    category_scores[control_name]["score"] += control_weight

        # Display vulnerabilities if there are any within the compliance report
        if failed_vulnerabilities:
            unique_vulnerabilities = set(failed_vulnerabilities)  # Remove duplicates
            device_report["vulnerabilities"] = list(unique_vulnerabilities)

        device_reports.append(device_report)
    overall_compliance_score = sum(data["score"] for data in category_scores.values()) / sum(
        data["weight"] for data in category_scores.values()) * 100

    # Generate report output
    report = [
        f"Network Compliance Report\n",
        f"Overall Security Compliance Score: {overall_compliance_score:.2f}%\n",
    ]

    for category, data in category_scores.items():
        report.append(f"{category} Compliance: {data['score'] / data['weight'] * 100:.2f}%\n")

    report.append("\nDevice Compliance Details:\n")

    for device in device_reports:
        report.append(f"{device['name']} ({device['ip']}):\n")
        for control, result in device["results"].items():
            if isinstance(result, dict):
                report.append(f"  - {control}:\n")
                if "Compliance Score" in result:
                    report.append(f"    - Compliance Score: {result['Compliance Score']}\n")
                if "Secure Ports Percentage" in result:
                    report.append(f"    - Secure Ports Percentage: {result['Secure Ports Percentage']}\n")
                if "Unsecured Ports" in result and result["Unsecured Ports"]:
                    report.append(f"    - Unsecured Ports:\n")
                    for port in result["Unsecured Ports"]:
                        report.append(f"      - {port}")
                if "Enabled/Total ports" in result and result["Enabled/Total ports"]:
                    report.append(f"    - Enabled Ports:\n")
                    report.append(result["Enabled/Total ports"])
                if "Disabled Ports" in result and result["Disabled Ports"]:
                    report.append(f"    - Disabled Ports:\n")
                    for port in result["Disabled Ports"]:
                        report.append(f"      - {port}")
                if "Trusted Ports" in result and result["Trusted Ports"]:
                    report.append(f"    - Trusted Ports:\n")
                    for port in result["Trusted Ports"]:
                        report.append(f"      - {port}")
            else:
                report.append(f"  - {control}: {result}\n")
        if "vulnerabilities" in device and device["vulnerabilities"]:
            report.append("  - Your network is vulnerable to the following attacks:\n")
            for vuln in device["vulnerabilities"]:
                report.append(f"    - {vuln}\n")

    general_overview = report
    general_overview.remove("\nDevice Compliance Details:\n")
    general_overview.remove("Network Compliance Report\n")
    
    print("Overview Report", report, "\n=======================================\n")
    report_data = device_reports
    create_pdf_report = input("Would you like to create a pdf report on the network compliance results (y/n):").lower()
    if create_pdf_report == "y" or create_pdf_report == "yes":
        # Create the reports directory if it doesn't exist
        from pathlib import Path
        Path('./reports').mkdir(parents=True, exist_ok=True)
        pdf_output_path = f"./reports/Network_Security_Compliance_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"

    # Continue with the report generation
        # Create PDF report using the formatted report data
        report_generation.generate_reports.generate_device_report_pdf(report_data, general_overview, pdf_output_path)

        # Optional: Add header and footer to the generated PDF
        header_image_path = "./Documentation/ARTEMIS_logo_1.jpg"
        report_generation.generate_reports.add_header(pdf_output_path, pdf_output_path, "letter", header_image_path)
        report_generation.generate_reports.add_footer(pdf_output_path, pdf_output_path, "letter", "ARTEMIS")

        print(Style.BRIGHT + f"Report generated successfully: {pdf_output_path}")
    else:
        print("")

    return "\n".join(report)




    



# Main loop to interact with the user
if __name__ == "__main__":
    while True:
        print("\nFramework-Based Controls")
        print("1. Apply Selective Controls")
        print("2. Back to Main Menu")

        choice = input("Enter your choice: ")
        if choice == "1":
            print("Applying Selective Controls...")
            compliance_report = selective_controls()
            print(compliance_report)
        elif choice == "2":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
