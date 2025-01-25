import sys
import os

#To allow importing from the parent directory
# Add the current script's directory to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Add all subdirectories of the parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
for root, dirs, files in os.walk(parent_dir):
    sys.path.append(root)

from colorama import Fore, Back, Style, init
# Initialize colorama
init(autoreset=True)


from connection_management.encrypted_connections import get_device_credentials
from connection_management.encrypted_connections import list_devices
from device_config import device_control 
def get_device_selection():
    devices = list_devices()
    if not devices:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No devices available.")
        exit()

    print(Style.BRIGHT + Fore.BLUE + "Available devices:")
    for i, device in enumerate(devices, 1):
        print(f"{i}. {device['devicename']} (IP: {device['ip']})")

    choice = int(input("Select a device by number: ")) - 1
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



if __name__ == "__main__":
    while True:
        print(Style.BRIGHT + Fore.BLUE + "\n=================================")
        print(Style.BRIGHT + "Attack Mitigation Menu")
        print(Style.BRIGHT + "\nWhat attacks would you like to mitigate?")
        print(Style.BRIGHT + "1. Disable Telnet (Unauthorized Access)")
        print(Style.BRIGHT + "2. Password Encryption (Password Attacks)")
        print(Style.BRIGHT + "3. Enable Secret (Password Attacks)")
        print(Style.BRIGHT + "4. Port Security (MAC Address Overflow)")
        print(Style.BRIGHT + "5. MOTD Banner (Unauthorized Access)")
        print(Style.BRIGHT + "6. Exec Timeout (Unauthorized Access)")
        print(Style.BRIGHT + "7. Syslog Configuration (Logging)")
        print(Style.BRIGHT + "8. BPDU Guard (STP Attack)")
        print(Style.BRIGHT + "9. Root Guard (STP Attack)")
        print(Style.BRIGHT + "10. Shutdown Ports (Network Misconfigurations)")
        print(Style.BRIGHT + "11. Activate Ports (Network Misconfigurations)")
        print(Style.BRIGHT + "12. Disable DTP (Network Misconfigurations)")
        print(Style.BRIGHT + "13. Disable CDP (Network Misconfigurations)")
        print(Style.BRIGHT + "14. DHCP Snooping (DHCP Starvation)")
        print(Style.BRIGHT + "15. Dynamic ARP Inspection (Data Integrity)")
        print(Style.BRIGHT + "16. Login Block (Brute-force Prevention)")
        print(Style.BRIGHT + "17. Exit")
        print(Style.BRIGHT + Fore.BLUE + "\n=================================")
        selected_controls = input(Style.BRIGHT + Fore.BLUE + "\nEnter your choices separated by commas: ").split(',')
        if '17' in selected_controls:
                print(Style.BRIGHT + Fore.YELLOW + "Exiting...")
                break
        device = get_device_selection()
    
        for control in selected_controls:
            control = control.strip()
            if control == '1':
                print(device_control.configure_disable_telnet(device))

            elif control == '2':
                print(device_control.configure_password_encryption(device))

            elif control == '3':
                secret_password = input("Enter enable secret password: ")
                print(device_control.configure_enable_secret(device, secret_password))

            elif control == '4':
                interface = input("Enter interface (e.g., FastEthernet0/1): ")
                max_mac_addresses = int(input("Enter maximum MAC addresses (default 1): ") or 1)
                violation_mode = input("Enter violation mode (restrict/protect/shutdown, default restrict): ") or 'restrict'
                print(device_control.configure_port_security(device, interface, max_mac_addresses, violation_mode))

            elif control == '5':
                banner_message = input(Style.BRIGHT + Fore.GREEN + "Enter MOTD banner message: ")
                print(device_control.configure_motd_banner(device, banner_message))

            elif control == '6':
                minutes = int(input(Style.BRIGHT + Fore.GREEN + "Enter exec timeout minutes: "))
                seconds = int(input(Style.BRIGHT + Fore.GREEN + "Enter exec timeout seconds: "))
                print(device_control.configure_exec_timeout(device, minutes, seconds))

            elif control == '7':
                syslog_server_ip = input(Style.BRIGHT + Fore.GREEN + "Enter Syslog server IP: ")
                print(device_control.configure_syslog(device, syslog_server_ip))

            elif control == '8':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                print(device_control.configure_bpdu_guard(device, interface))

            elif control == '9':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                print(device_control.configure_root_guard(device, interface))

            elif control == '10':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                print(device_control.shutdown_ports(device, interface))

            elif control == '11':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                print(device_control.activate_ports(device, interface))

            elif control == '12':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                print(device_control.disable_dtp(device, interface))

            elif control == '13':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (leave blank for global): ").strip()
                print(device_control.disable_cdp(device, interface if interface else None))

            elif control == '14':
                print(device_control.configure_dhcp_snooping(device))

            elif control == '15':
                vlan = int(input(Style.BRIGHT + Fore.GREEN + "Enter VLAN number (default 1): ") or 1)
                print(device_control.configure_dynamic_arp_inspection(device, vlan))

            elif control == '16':
                attempts = int(input(Style.BRIGHT + Fore.GREEN + "Enter maximum failed attempts: "))
                block_for = int(input(Style.BRIGHT + Fore.GREEN + "Enter block duration in seconds: "))
                within = int(input(Style.BRIGHT + Fore.GREEN + "Enter time frame in seconds: "))
                print(device_control.configure_login_block(device, attempts, block_for, within))

            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Invalid selection: {control}")

        continue_choice = input(Style.BRIGHT + Fore.GREEN + "\nDo you want to configure another device or make more changes? (y/n): ").lower()
        if continue_choice != 'y':
            break
