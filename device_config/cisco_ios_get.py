import sys
import os
from netmiko import ConnectHandler
import textfsm
import re
import io
# Add the current script's directory to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

# Add all subdirectories of the parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
for root, dirs, files in os.walk(parent_dir):
    sys.path.append(root)

def get_all_interfaces_on_device(device):
    """
    Retrieve all interfaces from the Cisco device.
    :param device: Dictionary containing device connection details for Netmiko.
    :return: List of all interface names.
    """
    interfaces = []
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | include ^interface ")
        connection.disconnect()
        # Extract interface names from the output
        for line in output.splitlines():
            if line.startswith('interface'):
                interface_name = line.split()[-1]
                # Skip VLAN interfaces
                if not interface_name.lower().startswith('vlan'):
                    interfaces.append(interface_name)
        return interfaces
    except Exception as error:
        return {"Error": str(error)}

def get_trunk_ports(device):
    """
    Retrieve unique trunk port names from the Cisco device.
    :param device: Dictionary containing device connection details for Netmiko.
    :return: List of unique trunk port names.
    """
    trunk_ports = set()
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show interfaces trunk")
        connection.disconnect()

        # Extract trunk port names from the output
        lines = output.splitlines()
        for line in lines:
            if line.startswith("Port") or line.startswith("----"):
                continue  # Skip header lines
            if len(line.strip()) > 0:
                port_name = line.split()[0]  # First column is the port name

                # Check and replace abbreviations with full names
                if port_name.startswith('Fa'):
                    port_name = port_name.replace('Fa', 'FastEthernet')
                elif port_name.startswith('Gi'):
                    port_name = port_name.replace('Gi', 'GigabitEthernet')
                elif port_name.startswith('Et'):
                    port_name = port_name.replace('Et', 'Ethernet')

                trunk_ports.add(port_name)  # Use a set to ensure unique values

        return list(trunk_ports)
    except Exception as error:
        return {"Error": str(error)}


def is_telnet_enabled(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | section line vty")
        connection.disconnect()
        return "Telnet access is enabled." if "transport input telnet" in output or "transport input telnet ssh" in output else "Telnet access is not enabled."
    except Exception as error:
        return f"Error checking Telnet status: {error}"

def is_ssh_enabled(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show ip ssh")
        connection.disconnect()
        return "SSH version 2 is enabled." if "SSH Enabled" in output and "version 2" in output else "SSH version 2 is not enabled."
    except Exception as error:
        return f"Error checking SSH status: {error}"

def check_password_encryption(device):
    try:
        with ConnectHandler(**device) as connection:
            connection.enable()
            output = connection.send_command("show running-config | section service password-encryption")
        if "no service password-encryption" in output:
            return "Password encryption is explicitly disabled."
        elif "service password-encryption" in output:
            return "Password encryption is enabled."
        else:
            return "Password encryption is not configured."
    except Exception as error:
        return f"Error checking password encryption: {error}"

def check_privilege_exec_password(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        
        # Send the command to check the enable secret configuration
        output = connection.send_command("show running-config | section enable secret")
        
        # Check if the output contains 'enable secret' followed by any encryption
        if "enable secret" in output:
            return "Enable secret is configured."
        else:
            return "Enable secret is not configured."
    
    except Exception as error:
        return f"Error checking enable secret: {error}"

def check_port_security_all_interfaces(device):
    port_security_status = {}
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        interface_output = connection.send_command("show ip interface brief")
        interface_lines = interface_output.splitlines()
        for line in interface_lines[1:]:
            columns = line.split()
            if columns and not columns[0].startswith("Vlan"):
                interface_name = columns[0]
                port_security_output = connection.send_command(f"show port-security interface {interface_name}")
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
                        port_security_status[interface_name]['Aging Time'] = ' '.join(line.split()[-2:])
                    elif "Total MAC Addresses" in line:
                        port_security_status[interface_name]['Current MAC Addresses'] = line.split()[-1]
                    elif "Security Violation Count" in line:
                        port_security_status[interface_name]['Violation Count'] = line.split()[-1]
        connection.disconnect()
        return port_security_status
    except Exception as error:
        # Return an error dictionary
        return {"error": f"Error checking port security: {error}"}


def check_cisco_ios_version(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show version")
        connection.disconnect()

        # Split output by lines and find the line starting with "Cisco IOS Software"
        lines = output.splitlines()
        for line in lines:
            if line.startswith("Cisco IOS Software"):
                # Extract the desired substring, ignoring extra details
                # Assuming format: "Cisco IOS Software, Linux Software (I86BI_LINUX-...)", 
                # we capture the part in parentheses
                ios_info = line.split(",")[1].strip()  # Extract Linux Software part
                version_info = line.split(",")[2].strip()  # Extract version part

                # Remove trailing part in brackets if present
                if "[" in version_info:
                    version_info = version_info.split("[")[0].strip() 
                return f"{ios_info}, {version_info}"        
                    
        return "Cisco IOS version information not found."
    except Exception as error:
        return f"Error retrieving Cisco IOS version: {error}"


def check_enable_motd(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | section banner motd")
        connection.disconnect()
        
        if output:
            # Remove 'banner motd' and '^C' characters from the output
            cleaned_output = output.replace("banner motd", "").replace("^C", "").strip()
            return cleaned_output if cleaned_output else "MOTD banner not configured."
        else:
            return "MOTD banner not configured."
    except Exception as error:
        return f"Error checking MOTD banner: {error}"

def check_syslog(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show logging")
        connection.disconnect()
        
        # Extract IP addresses and port numbers using regular expressions
        matches = re.findall(r'Logging to (\d+\.\d+\.\d+\.\d+) .*?port (\d+)', output)
        
        if matches:
            # Format the output as a list of strings "IP:Port"
            ip_port_list = [f"{ip}:{port}" for ip, port in matches]
            return ip_port_list
        else:
            return ["No remote logging enabled."]
    except Exception as error:
        return f"Error checking syslog configuration: {error}"

def check_exec_timeout(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | section line vty")
        connection.disconnect()

        # Extract exec-timeout value from the output
        match = re.search(r'exec-timeout (\d+) (\d+)', output)
        if match:
            minutes, seconds = match.groups()
            return f"Exec timeout is set to {minutes} minutes and {seconds} seconds."
        else:
            return "Exec timeout not configured for line vty 0 4."
    except Exception as error:
        return f"Error checking exec timeout: {error}"

def check_login_fail_lock(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | section login")
        connection.disconnect()
        
        if "login block-for" in output:
            return output.strip()
        else:
            return "Login block-for (fail lock) configuration not found."
    except Exception as error:
        return f"Error checking login fail lock configuration: {error}"


from netmiko import ConnectHandler

def check_bpdu_guard(device):
    bpdu_guard_status = {}
    try:
        # Establish connection to the device
        connection = ConnectHandler(**device)
        connection.enable()

        # Get the output of the BPDU Guard configuration
        output = connection.send_command("show running-config | include interface|spanning-tree bpduguard")
        connection.disconnect()
        # Parse through the output and extract interfaces where BPDU Guard is enabled
        interface_name = None
        for line in output.splitlines():
            if line.startswith('interface'):
                interface_name = line.split()[-1]
            elif "spanning-tree bpduguard enable" in line and interface_name != 'Vlan1':
                # If BPDU Guard is enabled on the interface, add it to the dictionary
                bpdu_guard_status[interface_name] = 'Enabled'

        # Disconnect after the command esxecution
        connection.disconnect()
        return bpdu_guard_status

    except Exception as error:
        # Handle any exceptions and return the error message
        return {"Error": str(error)}


def check_root_guard(device):
    root_guard_status = {}
    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Get the output of the Root Guard configuration
        output = connection.send_command("show running-config | include interface| spanning-tree guard root")
        
        # Print the output to troubleshoot

        # Parse through the output and extract interfaces where Root Guard is enabled
        interface_name = None
        for line in output.splitlines():
            if line.startswith('interface'):
                interface_name = line.split()[-1]
            elif "spanning-tree guard root" in line and interface_name != 'Vlan1':
                root_guard_status[interface_name] = 'Enabled'

        # Disconnect after the command execution
        connection.disconnect()

        # Return the final dictionary
        return root_guard_status

    except Exception as error:
        return {"Error": str(error)}

def check_shutdown_unused_ports(device):
    port_status = {}
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show ip interface brief")
        connection.disconnect()
        for line in output.splitlines()[1:]:
            columns = line.split()
            if columns and "administratively down" in columns:
                port_status[columns[0]] = "Administratively Down"
        return port_status
    except Exception as error:
        return {"Error": str(error)}
    
def check_active_ports(device):
    active_ports = {}
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show ip interface brief")
        connection.disconnect()
        for line in output.splitlines()[1:]:
            columns = line.split()
            if columns and "up" in columns[4].lower() and "up" in columns[5].lower():  # Adjusting column indices based on typical output structure
                active_ports[columns[0]] = "Active"
        return active_ports
    except Exception as error:
        return {"Error": str(error)}


def check_disable_dtp(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Retrieve output for all interfaces with trunk negotiation status
        output = connection.send_command("show interfaces switchport | include (Name|Negotiation)")
        connection.disconnect()

        # Split the output into lines for easier processing
        lines = output.splitlines()

        # Initialize list to store interfaces with "Negotiation of Trunking: On"
        on_interfaces = {}
        interface_name = None

        # Loop through the lines to find interfaces with "Negotiation of Trunking: On"
        for line in lines:
            if line.startswith("Name:"):  # Capture interface name
                interface_name = line.split()[1].strip()
                # Check and replace abbreviations with full names
                if interface_name.startswith('Fa'):
                    interface_name = interface_name.replace('Fa', 'FastEthernet')
                elif interface_name.startswith('Gi'):
                    interface_name = interface_name.replace('Gi', 'GigabitEthernet')
                elif interface_name.startswith('Et'):
                    interface_name = interface_name.replace('Et', 'Ethernet')
            elif "Negotiation of Trunking: Off" in line and interface_name:
                on_interfaces[interface_name] = "Off"

        return on_interfaces

    except Exception as error:
        return {"Error": str(error)}



def check_disable_cdp(device):
    """
    Checks for disabled CDP ports on a network device.

    Args:
        device: A dictionary containing device connection parameters 
                (e.g., host, username, password).

    Returns:
        A dictionary where keys are interface names and values are 
        "Disabled" if CDP is disabled on that interface, otherwise None.
    """
    disabled_ports = {}
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show running-config | section interface")
        connection.disconnect()

        lines = output.splitlines()
        for line in lines:
            if line.startswith("interface"):
                interface = line.split()[1]
            if "no cdp enable" in line:
                disabled_ports[interface] = "Disabled"

        return disabled_ports
    except Exception as error:
        return {"Error": str(error)}


def check_dhcp_snooping(device):
    """
    Checks DHCP Snooping configuration on a network device.

    Args:
        device: A dictionary containing device connection parameters 
                (e.g., host, username, password).

    Returns:
        A dictionary containing the following information:
            - "Globally Enabled": True if DHCP Snooping is globally enabled, 
                                 False otherwise.
            - "Interfaces": A dictionary where keys are interface names 
                            and values are "Trusted" if DHCP Snooping is 
                            enabled on that interface, otherwise None.
    """
    dhcp_snooping_status = {
        "Trusted Interfaces": {},
        "Untrusted Interfaces": {}
    }
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show ip dhcp snooping")
        connection.disconnect()

        lines = output.splitlines()
        for line in lines:
            # Check for interface lines in the specific format
            if line.startswith("Eth") or line.startswith("Fas") or line.startswith("Gig") and line.strip(): 
                interface = line.split()[0] 
                trusted = line.split()[1]
                if  trusted == 'no':
                    dhcp_snooping_status["Untrusted Interfaces"][interface] = "Untrusted" 
                elif trusted == 'yes':
                    dhcp_snooping_status["Trusted Interfaces"][interface] = "Trusted"


        return dhcp_snooping_status
    except Exception as error:
        return {"Error": str(error)}
    
def check_dynamic_arp_inspection(device):
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command("show ip arp inspection")
        connection.disconnect()
        return {
            "Dynamic ARP Inspection Status": output
        }
    except Exception as error:
        return {"Error": str(error)}

