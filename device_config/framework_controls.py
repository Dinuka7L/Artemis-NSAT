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


from colorama import Fore, Style, init
from connection_management.encrypted_connections import get_device_credentials, list_devices
import device_control
import sys

# Initialize colorama
init(autoreset=True)

# Mapping controls to functions
control_to_function_map = {
    "AC-6-3": [device_control.configure_enable_secret, device_control.configure_disable_telnet],
    "AC-6-5": [device_control.configure_password_encryption, device_control.configure_login_block],
    "AC-7": [device_control.configure_login_block],
    "CP-9": [device_control.configure_syslog],
    "4.3": [device_control.configure_exec_timeout],
    "12.3": [device_control.configure_disable_telnet],
    "13.9": [device_control.configure_port_security, device_control.shutdown_ports],
    "DTP-DISABLE": [device_control.disable_dtp],
    "CDP-DISABLE": [device_control.disable_cdp],
    "DHCP-SNOOPING": [device_control.configure_dhcp_snooping],
    "STP-PROTECTION": [device_control.configure_bpdu_guard, device_control.configure_root_guard],
}

# Function to get device selection
def get_device_selection(device_ip=None):
    if device_ip:
        # Use provided device IP
        credentials = get_device_credentials(device_ip)
        if not credentials:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"No credentials found for {device_ip}.")
            return None

        return {
            "device_type": "cisco_ios",
            "host": device_ip,
            "username": credentials[0]["username"],
            "password": credentials[0]["password"],
            "secret": credentials[0]["enable_secret"],
        }
    
    devices = list_devices()
    if not devices:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No devices available.")
        return None

    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "Available devices:")
    for i, device in enumerate(devices, 1):
        print(f"{i}. {device['devicename']} (IP: {device['ip']})")

    choice = int(input(Style.BRIGHT + Fore.GREEN + "Select a device by number: ")) - 1
    if choice < 0 or choice >= len(devices):
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid choice.")
        return None

    selected_device = devices[choice]
    target_ip = selected_device["ip"]
    credentials = get_device_credentials(target_ip)

    if not credentials:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"No credentials found for {target_ip}.")
        return None

    return {
        "device_type": "cisco_ios",
        "host": target_ip,
        "username": credentials[0]["username"],
        "password": credentials[0]["password"],
        "secret": credentials[0]["enable_secret"],
    }

# Function to get additional parameters based on the selected function
def get_additional_parameters(func):
    params = {}

    if func == device_control.configure_enable_secret:
        params['secret_password'] = input("Enter the secret password: ")
    elif func == device_control.configure_port_security:
        params['interface'] = input("Enter the interface (e.g., Gig0/1): ")
        params['max_mac_addresses'] = int(input("Enter the max MAC addresses (default 1): ") or 1)
        params['violation_mode'] = input("Enter the violation mode (restrict/shutdown) (default restrict): ") or 'restrict'
    elif func == device_control.configure_motd_banner:
        params['banner_message'] = input("Enter the MOTD banner message: ")
    elif func == device_control.configure_exec_timeout:
        params['minutes'] = int(input("Enter the timeout in minutes (default 10): ") or 10)
        params['seconds'] = int(input("Enter the timeout in seconds (default 0): ") or 0)
    elif func == device_control.configure_syslog:
        params['syslog_server_ip'] = input("Enter the Syslog server IP: ")
    elif func == device_control.configure_bpdu_guard or func == device_control.configure_root_guard:
        params['interfaces'] = input("Enter the interfaces (comma-separated, e.g., Gig0/1,Gig0/2): ").split(',')
    elif func == device_control.shutdown_ports or func == device_control.activate_ports:
        params['interface'] = input("Enter the interface to modify (e.g., Gig0/1): ")
    elif func == device_control.disable_dtp or func == device_control.disable_cdp:
        params['interface'] = input("Enter the interface (optional, press Enter to skip): ") or None
    elif func == device_control.configure_dynamic_arp_inspection:
        params['vlan'] = int(input("Enter the VLAN ID (default 1): ") or 1)
    elif func == device_control.configure_login_block:
        params['attempts'] = int(input("Enter the max login attempts (default 3): ") or 3)
        params['block_for'] = int(input("Enter the block time in seconds (default 60): ") or 60)
        params['within'] = int(input("Enter the time window in seconds (default 120): ") or 120)

    return params

# Main function for GUI integration
def apply_framework_control(device_ip, control_id):
    """
    Apply a framework control to a specific device
    Args:
        device_ip: IP address of the target device
        control_id: Framework control identifier
    """
    try:
        device = get_device_selection(device_ip)
        if not device:
            return f"Error: Could not get device configuration for {device_ip}"

        if control_id not in control_to_function_map:
            return f"Error: Unknown control ID: {control_id}"

        results = []
        for func in control_to_function_map[control_id]:
            try:
                # For GUI integration, use default parameters
                if func == device_control.configure_enable_secret:
                    result = func(device, "NewSecretPass123!")
                elif func == device_control.configure_exec_timeout:
                    result = func(device, 10, 0)
                elif func == device_control.configure_syslog:
                    result = func(device, "192.168.1.100")
                else:
                    result = func(device)
                
                results.append(f"✓ {func.__name__}: {result}")
            except Exception as e:
                results.append(f"✗ {func.__name__}: Error - {str(e)}")

        return f"Framework Control {control_id} applied to {device_ip}:\n" + "\n".join(results)

    except Exception as e:
        return f"Error applying framework control: {str(e)}"

# Main Execution for CLI
if __name__ == "__main__":
    if len(sys.argv) >= 3:
        # GUI mode - called with device IP and control ID
        device_ip = sys.argv[1]
        control_id = sys.argv[2]
        result = apply_framework_control(device_ip, control_id)
        print(result)
    else:
        # Interactive CLI mode
        while True:
            print(Fore.BLUE + "\n=================================")
            print(Style.BRIGHT + "Available Security Controls")

            controls = list(control_to_function_map.keys())
            for i, control in enumerate(controls, 1):
                print(f"{i}. {control}")

            print(Fore.BLUE + "\n=================================")
            print(Fore.GREEN + "Type 'exit' to quit the program.")
            selected_control_index = input(Style.BRIGHT + Fore.GREEN + "Enter the number of the control to execute: ").strip()

            if selected_control_index.lower() == "exit":
                print(Fore.YELLOW + "Exiting the program. Goodbye!")
                sys.exit()

            if not selected_control_index.isdigit() or int(selected_control_index) not in range(1, len(controls) + 1):
                print(Fore.RED + "Invalid selection. Please try again.")
                continue

            selected_control = controls[int(selected_control_index) - 1]
            print(Fore.YELLOW + f"Selected control: {selected_control}")

            device = get_device_selection()
            if not device:
                continue

            for func in control_to_function_map[selected_control]:
                params = get_additional_parameters(func)
                try:
                    result = func(device, **params)
                    print(f"✓ {result}")
                except Exception as e:
                    print(f"✗ Error: {str(e)}")