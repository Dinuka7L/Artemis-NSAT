from colorama import Fore, Back, Style, init
import json
# For running sub scripts and installing modules
import subprocess  
# Ensure netmiko is installed
def install_netmiko():
    try:
        from netmiko import ConnectHandler
    except ImportError:
        print("Netmiko not found. Installing...")
        subprocess.check_call(["python", "-m", "pip", "install", "netmiko"])
        from netmiko import ConnectHandler
    return ConnectHandler

ConnectHandler = install_netmiko()

# Initialize colorama
init(autoreset=True)

# JSON Database Structure
DATABASE_FILE = "network_compliance/security_controls.json"
DEFAULT_DATABASE = {
    "devices": {},
    "controls": {}
}

# Initialize Database
# Initialize Database
try:
    with open(DATABASE_FILE, 'r') as db_file:
        database = json.load(db_file)
except (FileNotFoundError, json.JSONDecodeError):
    print(f"{DATABASE_FILE} is missing or contains invalid JSON. Initializing with default data.")
    with open(DATABASE_FILE, 'w') as db_file:
        json.dump(DEFAULT_DATABASE, db_file, indent=4)
    database = DEFAULT_DATABASE


# Utility Functions
def save_database():
    with open(DATABASE_FILE, 'w') as db_file:
        json.dump(database, db_file, indent=4)



# main CLI Functions
def main_menu():
    print(Fore.RED +"""

 █████╗ ██████╗ ████████╗███████╗███╗   ███╗██╗███████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║██║██╔════╝
███████║██████╔╝   ██║   █████╗  ██╔████╔██║██║███████╗
██╔══██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║██║╚════██║
██║  ██║██║  ██║   ██║   ███████╗██║ ╚═╝ ██║██║███████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝╚══════╝

 Network Security Automation Toolkit
          Version 1.0                                                   
          """)
    while True:
        print( Fore.BLUE + "\n=================================")
        print(Style.BRIGHT  + """       Main Menu\n
1. Device Management\n
2. Device-Specific Configuration\n
3. Attack Mitigation\n
4. Enforce Framwork based Controls\n             
5. Network Compliance and benchmarking\n
6. Exit""")
        print(Fore.BLUE + "=================================")

        choice = input(  Fore.GREEN + Style.BRIGHT  + "Enter your choice >> ")
        if choice == "1":
            subprocess.run(["python", "connection_management/encrypted_connections.py"])
        elif choice == "2":
            config_or_retrieve = input(" [1] Configuration Retrive [2] Configuration Set: ")
            if config_or_retrieve == "1":
                subprocess.run(["python", "device_config/network_configuration_manager.py"])
            elif config_or_retrieve == "2":
                subprocess.run(["python", "device_config/device_control.py"])
            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid option. Please try again.")
        elif choice == "3":
            subprocess.run(["python", "device_config/attack_mitigation.py"])
        elif choice == "4":
            subprocess.run(["python", "device_config/framework_controls.py"])
        elif choice == "5":
            subprocess.run(["python", "network_compliance/check_compliance.py"])
        elif choice == "6":
            print(Style.BRIGHT + Fore.YELLOW  + "Exiting... Goodbye!")
            break
        else:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid option. Please try again.")



# Main Execution
if __name__ == "__main__":
    main_menu()
    input(Style.BRIGHT + "\nPress Enter to exit...")  # This will keep the terminal open until the user presses Enter.
