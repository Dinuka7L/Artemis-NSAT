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


from netmiko import ConnectHandler
from connection_management.encrypted_connections import get_device_credentials, list_devices

def get_device_selection():
    devices = list_devices()
    if not devices:
        print("No devices available.")
        exit()

    print("Available devices:")
    for i, device in enumerate(devices, 1):
        print(f"{i}. {device['devicename']} (IP: {device['ip']})")

    choice = int(input("Select a device by number: ")) - 1
    if choice < 0 or choice >= len(devices):
        print("Invalid choice.")
        exit()

    selected_device = devices[choice]
    target_ip = selected_device["ip"]
    credentials = get_device_credentials(target_ip)

    if not credentials:
        print(f"No credentials found for {target_ip}.")
        exit()

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

def configure_disable_telnet(device):
    try:
        # Establish connection
        connection = ConnectHandler(**device, timeout=120, session_log="telnet_ssh_config.log")
        
        # Get the actual prompt
        prompt = connection.find_prompt()
        connection.enable()

        # Send configuration commands to disable Telnet and enable SSH
        connection.send_config_set([
            "line vty 0 4",
            "transport input ssh"
        ])  

        # Optionally, exit configuration mode to ensure clean session
        connection.exit_config_mode()

        # Disconnect the session
        connection.disconnect()
        
        return "Telnet is now disabled on line vty 0 4."
    except Exception as error:
        return f"Error configuring disabling Telnet: {error}"


def configure_password_encryption(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            "service password-encryption"
        ])  

        # Optionally, exit configuration mode to ensure clean session
        connection.exit_config_mode()
        connection.disconnect()
        return "Password encryption enabled."
    except Exception as error:
        return f"Error enabling password encryption: {error}"

def configure_enable_secret(device, secret_password):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
           f"enable secret {secret_password}"
        ])  

        # Optionally, exit configuration mode to ensure clean session
        connection.exit_config_mode()
        connection.disconnect()
        return "Enable secret password configured."
    except Exception as error:
        return f"Error configuring enable secret: {error}"

def configure_port_security(device, interface, max_mac_addresses=1, violation_mode='restrict'):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        commands = [
            f"interface {interface}",
            f"switchport mode access",
            "switchport port-security",
            f"switchport port-security maximum {max_mac_addresses}",
            f"switchport port-security violation {violation_mode}"
        ]
        connection.send_config_set(commands)
        connection.exit_config_mode()
        connection.disconnect()
        return f"Port security configured on {interface}."
    except Exception as error:
        return f"Error configuring port security on {interface}: {error}"

def configure_motd_banner(device, banner_message):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        # Send the command as a string
        command = f"banner motd # {banner_message} #"
        connection.send_config_set([command])  # Use send_config_set for configuration commands
        connection.disconnect()
        return "MOTD banner configured."
    except Exception as error:
        return f"Error configuring MOTD banner: {error}"

def configure_exec_timeout(device, minutes=10, seconds=0):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
           f"line vty 0 4",
            f"exec-timeout {minutes} {seconds}"
        ])
        # Optionally, exit configuration mode to ensure clean session
        connection.exit_config_mode()        
        connection.disconnect()
        return "Exec timeout configured for line vty 0 4."
    except Exception as error:
        return f"Error configuring exec timeout: {error}"


def configure_syslog(device, syslog_server_ip):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"logging host {syslog_server_ip}",
            "logging trap informational"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return f"Syslog configured to send logs to {syslog_server_ip}."
    except Exception as error:
        return f"Error configuring syslog: {error}"



def configure_bpdu_guard(device, interfaces):
    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Loop through the list of interfaces and configure BPDU Guard
        for interface in interfaces:
            connection.send_config_set([
                f"interface {interface}",
                "spanning-tree bpduguard enable"
            ])

        connection.exit_config_mode()
        connection.disconnect()
        return f"BPDU Guard enabled on the following interfaces: {', '.join(interfaces)}."
    except Exception as error:
        return f"Error configuring BPDU Guard on the interfaces {', '.join(interfaces)}: {error}"


def configure_root_guard(device, interfaces):
    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Loop through the list of interfaces and configure Root Guard
        for interface in interfaces:
            connection.send_config_set([
                f"interface {interface}",
                "spanning-tree guard root"
            ])

        connection.exit_config_mode()
        connection.disconnect()
        return f"Root Guard enabled on the following interfaces: {', '.join(interfaces)}."
    except Exception as error:
        return f"Error configuring Root Guard on the interfaces {', '.join(interfaces)}: {error}"


def shutdown_ports(device, interface):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"interface {interface}",
            "shutdown"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return f"Interface {interface} administratively shut down."
    except Exception as error:
        return f"Error shutting down {interface}: {error}"


def activate_ports(device, interface):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"interface {interface}",
            "no shutdown"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return f"Interface {interface} activated."
    except Exception as error:
        return f"Error activating {interface}: {error}"


def disable_dtp(device, interface):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"interface {interface}",
            "switchport mode access",
            "switchport nonegotiate"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return f"DTP disabled on {interface}."
    except Exception as error:
        return f"Error disabling DTP on {interface}: {error}"


def disable_cdp(device, interface=None):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        if interface:
            commands = [
                f"interface {interface}",
                "no cdp enable"
            ]
        else:
            commands = ["no cdp run"]
        connection.send_config_set(commands)
        connection.exit_config_mode()
        connection.disconnect()
        return f"CDP disabled{' on ' + interface if interface else ''}."
    except Exception as error:
        return f"Error disabling CDP{' on ' + interface if interface else ''}: {error}"


def configure_dhcp_snooping(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        
        # Enable DHCP snooping globally
        connection.send_config_set(["ip dhcp snooping"])

        # Ask if the user wants to configure DHCP snooping on VLAN
        enable_vlan = input("Do you want to enable DHCP snooping on a specific VLAN (y/n)? ").lower()
        if enable_vlan == 'y':
            vlan = input("Enter VLAN number for DHCP snooping (default is 1): ")
            vlan = vlan if vlan else 1
            connection.send_config_set([f"ip dhcp snooping vlan {vlan}"])
        
        # Ask if the user wants to configure trusted interfaces
        configure_trust = input("Do you want to add a trust interface for DHCP snooping (y/n)? ").lower()
        if configure_trust == 'y':
            interface = input("Enter interface to configure as trusted (e.g., FastEthernet0/1): ")
            connection.send_config_set([f"interface {interface}", "ip dhcp snooping trust"])

        # Ask if the user wants to limit the DHCP rate on an interface
        configure_rate_limit = input("Do you want to configure rate limiting for DHCP on an interface (y/n)? ").lower()
        if configure_rate_limit == 'y':
            interface = input("Enter interface to configure rate limit (e.g., FastEthernet0/1): ")
            rate = input("Enter the rate limit (number of DHCP requests per second): ")
            connection.send_config_set([f"interface {interface}", f"ip dhcp snooping limit rate {rate}"])
            connection.exit_config_mode()
            connection.disconnect()
        return "DHCP snooping and related configurations applied successfully."
    except Exception as error:
        return f"Error configuring DHCP snooping: {error}"

def configure_dynamic_arp_inspection(device, vlan=1):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"ip arp inspection vlan {vlan}"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return f"Dynamic ARP Inspection enabled for VLAN {vlan}."
    except Exception as error:
        return f"Error configuring Dynamic ARP Inspection for VLAN {vlan}: {error}"


def configure_login_block(device, attempts=3, block_for=60, within=120):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        connection.send_config_set([
            f"login block-for {block_for} attempts {attempts} within {within}"
        ])
        connection.exit_config_mode()
        connection.disconnect()
        return "Login block configuration applied."
    except Exception as error:
        return f"Error configuring login block: {error}"


if __name__ == "__main__":
    print(Style.BRIGHT + Fore.BLUE +  "\n===========================================")
    print(Style.BRIGHT + Fore.BLUE + "Network Configurator")
    
    while True:
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "\n1. Configure Router")
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "2. Configure Switch")
        choice = input(Style.BRIGHT + Fore.GREEN +"Select an option (1 or 2): ")

        if choice not in ['1', '2']:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid choice. Please try again.")
            continue
        
        device = get_device_selection()
        
        print(Style.BRIGHT + "\nAvailable configurations:")
        print(Style.BRIGHT + "1. Disable Telnet")
        print(Style.BRIGHT + "2. Enable Password Encryption")
        print(Style.BRIGHT + "3. Configure Enable Secret")
        print(Style.BRIGHT + "4. Configure Port Security")
        print(Style.BRIGHT + "5. Configure MOTD Banner")
        print(Style.BRIGHT + "6. Configure Exec Timeout")
        print(Style.BRIGHT + "7. Configure Syslog")
        print(Style.BRIGHT + "8. Configure BPDU Guard")
        print(Style.BRIGHT + "9. Configure Root Guard")
        print(Style.BRIGHT + "10. Administratively Shutdown Ports")
        print(Style.BRIGHT + "11. Activate Ports")
        print(Style.BRIGHT + "12. Disable DTP")
        print(Style.BRIGHT + "13. Disable CDP")
        print(Style.BRIGHT + "14. Configure DHCP Snooping")
        print(Style.BRIGHT + "15. Configure Dynamic ARP Inspection")
        print(Style.BRIGHT + "16. Configure Login Block for Fail Lock")
        print(Style.BRIGHT + "17. Exit to main menu")
        print(Style.BRIGHT + Fore.BLUE +"\n===========================================")

        selected_controls = input(Style.BRIGHT + Fore.BLUE +"Select configurations to apply, separated by commas (e.g., 1,2,3): ").split(',')

        if not selected_controls:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "No configuration selected.")
            continue
        
        for control in selected_controls:
            if control == '1':
                result = configure_disable_telnet(device)
                print(result)

            elif control == '2':
                result = configure_password_encryption(device)
                print(result)

            elif control == '3':
                secret_password = input(Style.BRIGHT + Fore.GREEN +"Enter enable secret password: ")
                result = configure_enable_secret(device, secret_password)
                print(result)

            elif control == '4':
                interface = input(Style.BRIGHT + Fore.GREEN +"Enter interface (e.g., FastEthernet0/1): ")
                max_mac_addresses = input(Style.BRIGHT + Fore.GREEN +"Enter maximum allowed MAC addresses (default is 1): ")
                if not max_mac_addresses:
                    max_mac_addresses = 1
                else:
                    max_mac_addresses = int(max_mac_addresses)
                violation_mode = input(Style.BRIGHT + Fore.GREEN +"Enter violation mode (restrict, protect, or shutdown, default is 'restrict'): ")
                if not violation_mode:
                    violation_mode = 'restrict'
                result = configure_port_security(device, interface, max_mac_addresses, violation_mode)
                print(result)

            elif control == '5':
                banner_message = input(Style.BRIGHT + Fore.GREEN +"Enter MOTD banner message: ")
                result = configure_motd_banner(device, banner_message)
                print(result)

            elif control == '6':
                minutes = int(input(Style.BRIGHT + Fore.GREEN +"Enter exec timeout minutes: "))
                seconds = int(input(Style.BRIGHT + Fore.GREEN +"Enter exec timeout seconds: "))
                result = configure_exec_timeout(device, minutes, seconds)
                print(result)

            elif control == '7':
                syslog_server_ip = input(Style.BRIGHT + Fore.GREEN + "Enter Syslog server IP: ")
                result = configure_syslog(device, syslog_server_ip)
                print(result)

            elif control == '8':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                result = configure_bpdu_guard(device, interface)
                print(result)

            elif control == '9':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                result = configure_root_guard(device, interface)
                print(result)

            elif control == '10':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                result = shutdown_ports(device, interface)
                print(result)
                
            elif control == '11':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                result = activate_ports(device, interface)
                print(result)

            elif control == '12':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (e.g., FastEthernet0/1): ")
                result = disable_dtp(device, interface)
                print(result)

            elif control == '13':
                interface = input(Style.BRIGHT + Fore.GREEN + "Enter interface (optional, leave blank to disable globally): ")
                if interface.strip():
                    result = disable_cdp(device, interface)
                else:
                    result = disable_cdp(device)
                print(result)

            elif control == '14':
                result = configure_dhcp_snooping(device)
                print(result)

            elif control == '15':
                vlan = int(input(Style.BRIGHT + Fore.GREEN + "Enter VLAN number for Dynamic ARP Inspection (default is 1): ") or 1)
                result = configure_dynamic_arp_inspection(device, vlan)
                print(result)

            elif control == '16':
                attempts = int(input(Style.BRIGHT + Fore.GREEN + "Enter maximum failed attempts: "))
                block_for = int(input(Style.BRIGHT + Fore.GREEN + "Enter block duration in seconds: "))
                within = int(input(Style.BRIGHT + Fore.GREEN + "Enter time frame in seconds: "))
                result = configure_login_block(device, attempts, block_for, within)
                print(result)
            elif control == '17':
                print(Style.BRIGHT + Fore.YELLOW + "Exiting")
                break
            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Invalid control selection: {control}")
        
        continue_choice = input(Style.BRIGHT + Fore.GREEN + "\nDo you want to configure another device or make more changes? (y/n): ").lower()
        if continue_choice != 'y':
            break

