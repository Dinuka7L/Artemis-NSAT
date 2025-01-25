import paramiko

def retrieve_rules(interface, host, username, password):
    """Retrieve existing rules for a given interface on pfSense."""
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password, port=22)

        command = f'pfctl -sr | grep {interface}'
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error_output = stderr.read().decode('utf-8')

        ssh_client.close()

        print(f"\nFirewall Rules for Interface: {interface.upper()}")
        print("="*50)
        if error_output:
            print(f"Error: {error_output.strip()}")
        elif output:
            for idx, rule in enumerate(output.splitlines(), start=1):
                print(f"{idx}. {rule}")
        else:
            print("No rules found.")
        print("="*50)

    except Exception as e:
        print(f"\nError retrieving rules: {str(e)}")

def apply_rules(host, username, password, ruleset):
    """Apply the specified rules to pfSense."""
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password, port=22)

        # Create a temporary rules file
        sftp = ssh_client.open_sftp()
        remote_rules_file = "/tmp/custom_rules.conf"
        with sftp.open(remote_rules_file, "w") as remote_file:
            remote_file.write(ruleset + "\n")  # Ensuring newline at the end of rules
        sftp.close()

        # Load the rules using pfctl
        command = f"pfctl -f {remote_rules_file}"
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode("utf-8")
        error_output = stderr.read().decode("utf-8")

        if error_output:
            print(f"Error applying rules: {error_output.strip()}")
        else:
            print("Rules applied successfully.")

        ssh_client.close()

    except Exception as e:
        print(f"Error applying rules: {str(e)}")

def generate_rules(interface):
    """Generate automated firewall rules for a specific interface."""
    print(f"\nGenerating rules for interface: {interface}")

    rules = []

    # Example automated rules
    rules.append(f"pass in quick on {interface} proto tcp from any to any port 22")  # Allow SSH
    rules.append(f"pass in quick on {interface} proto icmp from any to any")        # Allow Ping
    rules.append(f"block in on {interface} from any to any")                      # Block all else

    return "\n".join(rules)

if __name__ == "__main__":
    print("1. Retrieve existing rules")
    print("2. Apply specified rules")
    print("3. Generate and apply automated rules")
    choice = input("\nSelect an option (1/2/3): ")

    host = input("\nEnter the pfSense IP address: ")
    username = input("Enter the username: ")
    password = input("Enter the password: ")

    if choice == "1":
        interface = input("\nEnter the interface name (e.g., em1, em2): ")
        retrieve_rules(interface, host, username, password)
    elif choice == "2":
        print("\nEnter your custom rules (type 'done' to finish):")
        rules = []
        while True:
            rule = input("Enter rule: ")
            if rule.lower() == "done":
                break
            rules.append(rule)
        ruleset = "\n".join(rules)
        apply_rules(host, username, password, ruleset)
    elif choice == "3":
        interface = input("\nEnter the interface name (e.g., em1, em2): ")
        ruleset = generate_rules(interface)
        print("\nGenerated Rules:")
        print(ruleset)
        confirm = input("\nApply these rules? (yes/no): ").lower()
        if confirm == "yes":
            apply_rules(host, username, password, ruleset)
        else:
            print("Rules not applied.")
    else:
        print("\nInvalid choice. Please select 1, 2, or 3.")
