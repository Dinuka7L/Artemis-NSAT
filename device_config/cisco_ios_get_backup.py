import sys
import os

# Add the current script's directory to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Add all subdirectories of the parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
for root, dirs, files in os.walk(parent_dir):
    sys.path.append(root)

from netmiko import ConnectHandler
from device_config.network_configuration_manager import get_device_selection


def is_telnet_enabled(device):
    
    try:
        # Establish connection to the device
        connection = ConnectHandler(**device)
        connection.enable()

        # Fetch the configuration of the VTY lines
        output = connection.send_command("show running-config | section line vty")
        print(f"VTY Configuration Output:\n{output}")
        
        # Check if Telnet is enabled
        if "transport input telnet" in output or "transport input telnet ssh" in output:
            print("Telnet access is enabled.")
        else:
            print("Telnet access is not enabled.")
        
        # Disconnect from the device
        connection.disconnect()
    except Exception as error:
        print(f"An error occurred: {error}")


def is_ssh_enabled(device):
    try:
        # Establish a connection to the Cisco device
        connection = ConnectHandler(**device)
        connection.enable()
        
        # Execute the command to check SSH configuration
        output = connection.send_command("show ip ssh")
        
        # Print the output for debugging
        print(f"SSH Configuration Output:\n{output}")
        
        # Determine if SSH version 2 is enabled
        if "SSH Enabled" in output and "version 2" in output:
            print("SSH version 2 is enabled.")
        else:
            print("SSH version 2 is not enabled.")
        
        # Disconnect from the device
        connection.disconnect()
        
    except Exception as error:
        print(f"An error occurred: {error}")

def check_password_encryption(device):
    """
    Check if password encryption is enabled or explicitly disabled on the Cisco device.
    """
    command = "show running-config | section service password-encryption"
    try:
        with ConnectHandler(**device) as net_connect:
            # Enter enable mode
            net_connect.enable()
            print(f"Executing command: {command}")
            output = net_connect.send_command(command)  
        # Connect to the device
        #connection = ConnectHandler(**device)
        
        # Execute the command to check the configuration
        #output = connection.send_command("show running-config | include service password-encryption")
        print("Received Output:", output)
        
        # Check for both enabled and explicitly disabled cases
        if "service password-encryption" == output:
            print("Password encryption is enabled.")
        elif "no service password-encryption" == output:
            print("Password encryption is explicitly disabled.")
        else:
            print("Password encryption is not configured.")
        
        # Disconnect from the device
        #connection.disconnect()
    except Exception as error:
        print(f"An error occurred while checking password encryption: {error}")


def check_privilege_exec_password(device):
    """
    Check if 'enable secret' is configured on the Cisco device.
    """
    try:
        # Connect to the device
        connection = ConnectHandler(**device)

        # Execute the command to get the full running-config
        connection.enable()
        output = connection.send_command("show running-config | section enable secret")
        
        # Print the full output for debugging
        print(f"Running Config Output: \n{output}")

        # Check if 'enable secret' is in the output
        if "enable secret" in output:
            print("Enable secret is configured.")
        else:
            print("Enable secret is not configured.")

        # Disconnect from the device
        connection.disconnect()
    
    except Exception as error:
        print(f"An error occurred while checking enable secret: {error}")
        
        
def check_port_security_all_interfaces(device):
    """
    Check the status of port security on all interfaces of a Cisco device, excluding VLAN interfaces.

    Returns:
        dict: A dictionary containing port security status for each interface.
    """
    port_security_status = {}

    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Get a list of all interfaces
        interface_output = connection.send_command("show ip interface brief")

        # Extract interface names and skip VLANs
        interface_lines = interface_output.splitlines()
        for line in interface_lines[1:]:  # Skip the header row
            columns = line.split()
            if columns and not columns[0].startswith("Vlan"):
                interface_name = columns[0]
                port_security_output = connection.send_command(f"show port-security interface {interface_name}")
                print(port_security_output)
                port_security_status[interface_name] = {
                    'Port Security Enabled': 'Enabled' if "Port Security" in port_security_output and "Enabled" in port_security_output else 'Disabled',
                    'Port Status': None,
                    'Violation Mode': None,
                    'Aging Time': None,
                    'Max MAC Addresses': None,
                    'Current MAC Addresses': None,
                    'Violation Count': None,
                }

                for line in port_security_output.splitlines():
                    if "Maximum MAC Addresses" in line:
                        port_security_status[interface_name]['Max MAC Addresses'] = line.split()[-1]
                    elif "Port Status" in line:
                        port_security_status[interface_name]['Port Status'] = line.split()[-1]
                    elif "Violation Mode" in line:
                        port_security_status[interface_name]['Violation Mode'] = line.split()[-1]
                    elif "Aging Time" in line:
                        # Extract both the numeric part and "mins"
                        aging_time_parts = line.split()[-2:]  # Get the last two items
                        port_security_status[interface_name]['Aging Time'] = ' '.join(aging_time_parts)  # Join with a space
                    elif "Total MAC Addresses" in line:
                        port_security_status[interface_name]['Current MAC Addresses'] = line.split()[-1]
                    elif "Security Violation Count" in line:
                        port_security_status[interface_name]['Violation Count'] = line.split()[-1]


        connection.disconnect()

    except Exception as error:
        print(f"An error occurred while checking port security: {error}")
    print(port_security_status)
    return port_security_status





# Commands to check the status of security features
commands = {
    "port_security": "show port-security interface e0/0",
    "bpdu_guard": "show running-config | include bpduguard",
    "root_guard": "show running-config | include guard root",
    "shutdown_unused_ports": "show ip interface brief | include administratively down",
    "disable_dtp": "show running-config | include nonegotiate",
    "disable_cdp": "show cdp neighbors",
    "dhcp_snooping": "show ip dhcp snooping",
    "dynamic_arp_inspection": "show ip arp inspection",
    "mac_address_overflow": "show port-security address"
}



# Check each feature manually here for testing wihtout the CLI
def connect_to_device():
    device = get_device_selection()
    connection = ConnectHandler(**device)
    for feature, command in commands.items():
        output = connection.send_command(command)
        print(f"{feature}:")
        print(output)
        print("\n")
    # Disconnect from the device
    connection.disconnect()

