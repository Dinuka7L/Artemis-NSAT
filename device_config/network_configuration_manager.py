import sys
import os
from datetime import datetime
import subprocess
#To allow importing from the parent directory
# Add the current script's directory to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Add all subdirectories of the parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
for root, dirs, files in os.walk(parent_dir):
    sys.path.append(root)


from colorama import Fore, Back, Style, init
init(autoreset=True)


import cisco_ios_get
import device_control
import report_generation.generate_reports  

from connection_management.encrypted_connections import get_device_credentials
from connection_management.encrypted_connections import list_devices
 
from reportlab.lib.pagesizes import landscape, letter

def get_device_selection():
    devices = list_devices()
    if not devices:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No devices available.")
        exit()

    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "Available devices:")
    for i, device in enumerate(devices, 1):
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{i}. {device['devicename']} (IP: {device['ip']})")

    choice = int(input(Style.BRIGHT + Fore.GREEN + "Select a device by number: ")) - 1
    if choice < 0 or choice >= len(devices):
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid choice.")
        exit()

    selected_device = devices[choice]
    target_ip = selected_device["ip"]
    credentials = get_device_credentials(target_ip)

    if not credentials:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"No credentials found for {target_ip}.")
        exit()

    device_name = selected_device["devicename"]  # Use the selected device's name
    username = credentials[0]["username"]
    password = credentials[0]["password"]
    enable_secret = credentials[0]["enable_secret"]
    device = {
        "device_type": "cisco_ios",
        "host": target_ip,
        "username": username,
        "password": password,
        "secret": enable_secret,
    }
    return device 


def get_multiple_device_selection():
    """
    Prompts the user to select one or more devices from a list and returns the selected
    devices as a list of dictionaries with their details.

    Returns:
        list: A list of dictionaries containing device connection details.
    """
    devices = list_devices()
    if not devices:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No devices available.")
        exit()

    print(Style.BRIGHT + Fore.BLUE + "Available devices:")
    for i, device in enumerate(devices, 1):
        print(Style.BRIGHT + Fore.BLUE + f"{i}. {device['devicename']} (IP: {device['ip']})")

    choices = input(Style.BRIGHT + Fore.GREEN + "Select device numbers separated by commas (e.g., 1,3,5): ").strip().split(',')
    selected_devices = []

    for choice in choices:
        try:
            index = int(choice) - 1
            if index < 0 or index >= len(devices):
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Invalid choice: {choice}. Skipping.")
                continue

            selected_device = devices[index]
            target_ip = selected_device["ip"]
            credentials = get_device_credentials(target_ip)

            if not credentials:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"No credentials found for {target_ip}. Skipping.")
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
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Invalid input: {choice}. Skipping.")

    if not selected_devices:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No valid devices were selected.")
        exit()

    return selected_devices

def configure_router():
    # Device type-specific control options (for routers)
    device_controls = {
        "router":  [
            "1. Check if Telnet is enabled",
            "2. Check if SSH v2 is enabled",
            "3. Check if password encryption is enabled",
            "4. Check if privilege exec mode password is set",
            "5. Check if Cisco IOS version is up to date",
            "6. Check if MOTD (Message of the Day) banner is configured",
            "7. Check if Syslog is configured",
            "8. Check Exec timeout settings"
        ]
    }

    while True:
        device = get_device_selection()
        
        print(Style.BRIGHT + Fore.BLUE + "\nAvailable configurations to check:")
        # Display the available checks for routers
        for option in device_controls["router"]:
            print(option)
        
        check_choice = input(Style.BRIGHT + Fore.GREEN + "Enter the numbers of the checks to perform (e.g., 1,3,5): ").split(',')
        
        for selected_option in check_choice:
            selected_option = selected_option.strip()
            if selected_option == "1":
                result = cisco_ios_get.is_telnet_enabled(device)
                print(result)
            elif selected_option == "2":
                result = cisco_ios_get.is_ssh_enabled(device)
                print(result)
            elif selected_option == "3":
                result = cisco_ios_get.check_password_encryption(device)
                print(result)
            elif selected_option == "4":
                result = cisco_ios_get.check_privilege_exec_password(device)
                print(result)
            elif selected_option == "5":
                result = cisco_ios_get.check_cisco_ios_version(device)
                print(result)
            elif selected_option == "6":
                result = cisco_ios_get.check_enable_motd(device)
                print(result)
            elif selected_option == "7":
                result = cisco_ios_get.check_syslog(device)
                print(result)
            elif selected_option == "8":
                result = cisco_ios_get.check_exec_timeout(device)
                print(result)
            else:
                print(f"Invalid option: {selected_option}")
        
        print(Style.BRIGHT + "Exiting Router Check Configuration")
        break


def configure_switch():
    device = get_device_selection()
    while True:
        print(Style.BRIGHT +"\nSwitch Configuration Checks:")
        print(Style.BRIGHT +"1. Check if telnet is enabled")
        print(Style.BRIGHT +"2. Check if ssh v2 is enabled")
        print(Style.BRIGHT + "3. Check if password encryption is enabled")
        print(Style.BRIGHT + "4. Check if privilege exec mode password is set")
        print(Style.BRIGHT + "5. Check IOS Version")
        print(Style.BRIGHT + "6. Check Message Of the Day Warning")
        print(Style.BRIGHT + "7. Check logging status")
        print(Style.BRIGHT + "8. Check Remote Login Execution Timeout")
        print(Style.BRIGHT + "9. Check Port Security status in switch")
        print(Style.BRIGHT + "10. Check BPDU Guard")
        print(Style.BRIGHT + "11. Check Root Guard")
        print(Style.BRIGHT + "12. Check Administratively Shutdown Ports")
        print(Style.BRIGHT + "13. Check Administratively Active Ports")
        print(Style.BRIGHT + "14. Check DTP Nonegotiate Ports")
        print(Style.BRIGHT + "15. Check CDP Disabled Ports")
        print(Style.BRIGHT + "16. Check IP DHCP Snooping Status")
        print(Style.BRIGHT + "17. Check IP ARP Inspection Status")
        print(Style.BRIGHT + "18. Check Login Fail Lock Status")
        print(Style.BRIGHT + "19. Back to Main Menu")
        
        check_choice = input(Style.BRIGHT + Fore.GREEN + "Enter the numbers of the checks to perform (e.g., 1,3,5): ").split(',')
        
        # Loop through each selected option
        for selected_option in check_choice:
            if selected_option == "1":
                print(cisco_ios_get.is_telnet_enabled(device))
            elif selected_option == "2":
                print(cisco_ios_get.is_ssh_enabled(device))
            elif selected_option == "3":
                print(cisco_ios_get.check_password_encryption(device))
            elif selected_option == "4":
                print(cisco_ios_get.check_privilege_exec_password(device))
            elif selected_option == "5":
                print(cisco_ios_get.check_cisco_ios_version(device))
            elif selected_option == "6":
                print(cisco_ios_get.check_enable_motd(device))
            elif selected_option == "7":
                print(cisco_ios_get.check_syslog(device))
            elif selected_option == "8":
                print(cisco_ios_get.check_exec_timeout(device))
            elif selected_option == "9":
                port_security_status = cisco_ios_get.check_port_security_all_interfaces(device)
                print("\nPort Security Status for All Interfaces:\n")
                for interface, settings in port_security_status.items():
                    print(f"Interface: {interface}")
                    for key, value in settings.items():
                        print(f"  {key}: {value}")
                    print("-" * 50)
            elif selected_option == "10":
                bpdu_guard_status = cisco_ios_get.check_bpdu_guard(device)
                
                if not bpdu_guard_status:
                    print("No BPDU Guard configuration found.")
                else:
                    print("BPDU Guard enabled on the following interfaces:")
                    for interface, status in bpdu_guard_status.items():
                        print(f"Interface {interface}: {status}")
            elif selected_option == "11":
                print(cisco_ios_get.check_root_guard(device))
            elif selected_option == "12":
                print(cisco_ios_get.check_shutdown_unused_ports(device))
            elif selected_option == "13":
                print(cisco_ios_get.check_active_ports(device))
            elif selected_option == "14":
                print(cisco_ios_get.check_disable_dtp(device))
            elif selected_option == "15":
                print(cisco_ios_get.check_disable_cdp(device))
            elif selected_option == "16":
                print(cisco_ios_get.check_dhcp_snooping(device))
            elif selected_option == "17":
                print(cisco_ios_get.check_dynamic_arp_inspection(device))
            elif selected_option == "18":
                print(cisco_ios_get.check_login_fail_lock(device))
            elif selected_option == "19":
                print("Exiting to Main Menu...")
                return  # Exit the function and return to the main menu
            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid choice. Please enter a number between 1 and 19.")
        
        # Ensure the loop continues until the user selects the exit option

            
def generate_network_security_posture_report(selected_devices):
    """
    Generates a network security posture report for selected devices.
    
    Args:
        selected_devices (list): List of device details dictionaries.
    """
    from collections import defaultdict
    selected_controls = defaultdict(list)

    # Device type-specific control options
    device_controls = {
        "router": ["1. Telnet Enabled", "2. SSH Enabled", "3. Password Encryption", 
                   "4. Privilege Exec Password", "5. Cisco IOS Version", 
                   "6. Enable MOTD", "7. Syslog", "8. Exec Timeout"],


        "switch": ["1. Telnet Enabled", "2. SSH Enabled", "3. Password Encryption", 
                   "4. Privilege Exec Password", "5. Cisco IOS Version", 
                   "6. Enable MOTD", "7. Syslog", "8. Exec Timeout",
                   "9. Port Security on Interfaces", "10. BPDU Guard", "11. Root Guard", 
                   "12. Administratively Shutdown Ports", "13. Active Ports", 
                   "14. Disable DTP", "15. Disable CDP", "16. DHCP Snooping", 
                   "17. Dynamic ARP Inspection", "18. Login Fail Lock"],
        # Add more device categories and controls as needed
    }
    
    report_data = []

    # Iterate over devices and generate control list based on type
    for device in selected_devices:
        print(device)
        device_type = device["device_category"].lower()
        device_name = device["device_name"]
        device_ip = device["host"]
        print(Style.BRIGHT + Fore.BLUE + f"\nConfiguring report for {device_type} '{device_name}' (IP: {device_ip})")

        available_controls = device_controls.get(device_type, [])
        if not available_controls:
            print(Style.BRIGHT + Fore.BLUE + f"No predefined controls for {device_type}. Skipping.")
            continue
        
        # Display available controls
        print(Style.BRIGHT + Fore.BLUE + "Available security controls for this device:")
        for control in available_controls:
            print(control)
        
        control_selection = input(f"Select controls for {device_name} (e.g., 1,3,5): ").split(',')
        selected_controls[device_name] = [available_controls[int(choice) - 1] for choice in control_selection if choice.isdigit()]

        device_report = {"name": device_name, "ip": device_ip, "results": {}}
        print("Device:",device)
        device_details_formatted = device
        del device_details_formatted['device_category']
        del device_details_formatted['device_name']

        # Define control functions to gather data for selected controls
        control_functions = {
            "1": {
                "get_func": lambda: cisco_ios_get.is_telnet_enabled(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_telnet_status(result)
            },
            "2": {
                "get_func": lambda: cisco_ios_get.is_ssh_enabled(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_ssh_version_status(result)
            },
            "3": {
                "get_func": lambda: cisco_ios_get.check_password_encryption(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_password_encryption(result)
            },
            "4": {
                "get_func": lambda: cisco_ios_get.check_privilege_exec_password(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_enable_secret(result)
            },
            "5": {
                "get_func": lambda: cisco_ios_get.check_cisco_ios_version(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_cisco_ios_version(result)
            },
            "6": {
                "get_func": lambda: cisco_ios_get.check_enable_motd(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_banner_motd(result)
            },
            "7": {
                "get_func": lambda: cisco_ios_get.check_syslog(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_syslog(result[0])
            },
            "8": {
                "get_func": lambda: cisco_ios_get.check_exec_timeout(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_exec_timeout(result)
            },
            "9": {
                "get_func": lambda: cisco_ios_get.check_port_security_all_interfaces(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_port_security_status_dict(result)
            },
            "10": {
                "get_func": lambda: cisco_ios_get.check_bpdu_guard(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_bpdu_guard_status(result)
            },
            "11": {
                "get_func": lambda: cisco_ios_get.check_root_guard(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_root_guard_status(result)
            },
            "12": {
                "get_func": lambda: cisco_ios_get.check_shutdown_unused_ports(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_unused_ports_status(result)
            },
            "13": {
                "get_func": lambda: cisco_ios_get.check_active_ports(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_active_ports_status(result)
            },
            "14": {
                "get_func": lambda: cisco_ios_get.check_disable_dtp(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_disable_dtp_status(result)
            },
            "15": {
                "get_func": lambda: cisco_ios_get.check_disable_cdp(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_disable_cdp_status(result)
            },
            "16": {
                "get_func": lambda: cisco_ios_get.check_dhcp_snooping(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_dhcp_snooping_status(result)
            },
            "17": {
                "get_func": lambda: cisco_ios_get.check_dynamic_arp_inspection(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_dynamic_arp_inspection_status(result)
            },
            "18": {
                "get_func": lambda: cisco_ios_get.check_login_fail_lock(device_details_formatted),
                "process_func": lambda result: report_generation.generate_reports.generate_login_fail_lockdown_status(result)
            }
            
        }
        cisco_ios_version = cisco_ios_get.check_cisco_ios_version(device_details_formatted)
        device_report["ios_version"] = cisco_ios_version
        # Iterate over control selections and apply both functions
        for choice in control_selection:
            try:
                control_pair = control_functions.get(choice)
                if control_pair:
                    # Retrieve data using the 'get' function
                    raw_result = control_pair["get_func"]()
                    # Process the result using the 'process' function
                    processed_result = control_pair["process_func"](raw_result)
                    device_report["results"][choice] = processed_result
                else:
                    device_report["results"][choice] = "Function not implemented."
            except Exception as e:
                device_report["results"][choice] = f"Error: {str(e)}"

        report_data.append(device_report)
        print("REPORT DATA:", report_data)
    
    

# Create the reports directory if it doesn't exist
    if not os.path.exists('./reports'):
        os.makedirs('./reports')
    pdf_output_path = f"./reports/Network_Security_Posture_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"

# Continue with the report generation

    # Create PDF report using the formatted report data
    report_generation.generate_reports.create_pdf_report(report_data, pdf_output_path)

    # Optional: Add header and footer to the generated PDF
    header_image_path = "./Documentation/ARTEMIS_logo_1.jpg"
    report_generation.generate_reports.add_header(pdf_output_path, pdf_output_path, "letter", header_image_path)
    report_generation.generate_reports.add_footer(pdf_output_path, pdf_output_path, "letter", "ARTEMIS")
    
    print(Style.BRIGHT + f"Report generated successfully: {pdf_output_path}")



if __name__ == "__main__":
    while True:
            print(Fore.BLUE +"\n=================================")
            print(Style.BRIGHT+"Network Configuration Manager")
            print(Style.BRIGHT+ Fore.CYAN + """\nDevice-Specific Configuration Retrieval
1. Retrieve Configuration of Routers
2. Retrieve Configuration of Switches
3. Retrieve Configuration of Servers
4. CRetrieve Configuration of Firewall
5. Generate Network Security Posture Report
6. Back to Main Menu""")	
            print(Fore.BLUE +"\n=================================")

            choice = input(Style.BRIGHT + Fore.GREEN+ "Enter your choice >> ")
            print("\n##############")
            if choice == "1":
                print(Style.BRIGHT + "Retrieve Configuration of Routers")
                configure_router()
                
            elif choice == "2":
                print(Style.BRIGHT +"Retrieve Configuration of Switches")
                configure_switch()
                
            elif choice == "3":
                print(Style.BRIGHT +"Retrieve Configuration of Servers")
                
            elif choice == "4":
                subprocess.run(["python", "device_config/firewall_config.py"])
            elif choice == "5":
                print(Style.BRIGHT + "Generate Network Security Posture Report")
                devices_selection = get_multiple_device_selection()
                generate_network_security_posture_report(devices_selection)
            elif choice == "6":
                print(Style.BRIGHT + "Exiting to Main Menu...")
                break

            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid option. Please try again.")

            