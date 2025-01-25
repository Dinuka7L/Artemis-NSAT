from netmiko import ConnectHandler
from colorama import Fore, Back, Style, init
init(autoreset=True)


def update_device_password(ip, username, old_password, old_enable_secret, new_password, new_enable_secret=None):
    """
    Updates the SSH user password on a Cisco IOS device.
    If a new enable secret is provided, it updates that as well.
    """
    device = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': username,
        'password': old_password,
        'secret': old_enable_secret,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()

            # Update the user password
            config_commands = [
                f"username {username} password {new_password}"
            ]
            net_connect.send_config_set(config_commands)
            print(f"Device password updated successfully for user {username}.")

            # If a new enable secret is provided, update it
            if new_enable_secret:
                config_commands = [
                    f"enable secret {new_enable_secret}"
                ]
                net_connect.send_config_set(config_commands)
                print("Enable secret updated successfully.")

            return True
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    if new_enable_secret:
        try:
            with ConnectHandler(**device) as net_connect:
                net_connect.enable()

                config_commands = [
                    f"line vty 0 4",
                    f"enable secret {new_enable_secret}",
                    f"login"   
                ]

                net_connect.send_config_set(config_commands)
                print(f"Device password updated successfully for user {username}.")
                return True
        except Exception as e:
            print(f"Error: {e}")
            return False


def update_device_secret(ip, username, old_password, old_enable_secret, new_enable_secret):
    """
    Updates the enable secret on a Cisco IOS device.
    """

    device = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': username,
        'password': old_password,
        'secret': old_enable_secret,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()

            config_commands = [

                f"line vty 0 4",
                f"enable secret {new_enable_secret}",
                f"login"
            ]

            net_connect.send_config_set(config_commands)
            print("Device enable secret updated successfully.")
            return True
    except Exception as e:
        print(f"Error: {e}")
        return False
