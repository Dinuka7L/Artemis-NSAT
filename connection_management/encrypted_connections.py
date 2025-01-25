import os
import json
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
import base64
import secrets
from connections_manager import update_device_password, update_device_secret


from colorama import Fore, Back, Style, init
# Initialize colorama
init(autoreset=True)

script_directory = os.path.dirname(os.path.abspath(__file__))

VALID_DEVICE_CATEGORIES = {"router", "switch", "firewall", "server"}

CREDENTIALS_FILE = os.path.join(script_directory, "encrypted_credentials.json")
KEY_FILE = os.path.join(script_directory, "key.key")
SALT_FILE = os.path.join(script_directory, "salt.bin")

BLOCK_SIZE = 128

IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

def generate_key():
    if not os.path.exists(KEY_FILE) or not os.path.exists(SALT_FILE):
        password = secrets.token_bytes(32)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(password)
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(password)
        with open(SALT_FILE, "wb") as salt_file:
            salt_file.write(salt)

def load_key():
    with open(KEY_FILE, "rb") as key_file:
        password = key_file.read()
    with open(SALT_FILE, "rb") as salt_file:
        salt = salt_file.read()
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_data(data, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_data(encrypted_data, key):
    backend = default_backend()
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def validate_ip(ip):
    if not re.match(IP_REGEX, ip):
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid IP address format.")
        return False
    return True

def validate_device_name(devicename):
    if len(devicename) <= 2:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Device name must be more than 2 characters.")
        return False
    return True

def validate_username(username):
    if len(username) <= 3:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Username must be more than 3 characters.")
        return False
    return True



def validate_device_category(category):
    if category.lower() not in VALID_DEVICE_CATEGORIES:
        print(f"Style.BRIGHT + Fore.LIGHTRED_EX + Invalid device category '{category}'. Please choose from {', '.join(VALID_DEVICE_CATEGORIES)}.")
        return False
    return True


def prompt_for_new_credentials(ip, username, devicename, old_password, old_enable_secret, device_category):
    new_password = None
    new_enable_secret = None

    if len(old_password) < 8:
        update_current_ssh_pass = input(Style.BRIGHT + Fore.GREEN + "Your Current SSH Login Password is weak. \n Would you like to update the password?(y/n):").lower()
        if update_current_ssh_pass in ["yes", "y"]:
            new_password = input(Style.BRIGHT + Fore.GREEN + "Enter a new strong SSH password (at least 8 characters): ")
            while len(new_password) < 8:
                new_password = input(Style.BRIGHT + Fore.GREEN + "Password must be at least 8 characters. Please try again: ")
        else:
            save_credentials(ip, username, devicename, old_password, old_enable_secret, device_category)

    if len(old_enable_secret) < 8:
        update_current_secret_pass = input(Style.BRIGHT + Fore.GREEN + "Your Current device secret is weak. \n Would you like to update the password?(y/n):").lower()
        if update_current_secret_pass in ["yes", "y"]:
            new_enable_secret = input(Style.BRIGHT + Fore.GREEN + "Enter a new strong enable secret (at least 8 characters): ")
            while len(new_enable_secret) < 8:
                new_enable_secret = input(Style.BRIGHT + Fore.GREEN + "Enable secret must be at least 8 characters. Please try again: ")
        else:
            save_credentials(ip, username, devicename, old_password, old_enable_secret, device_category)

    print(Style.BRIGHT + Fore.LIGHTCYAN_EX +"Updating credentials on the network device...")
    if new_password and new_enable_secret:
        success = update_device_password(ip, username, old_password, old_enable_secret, new_password, new_enable_secret)
    elif new_password:
        success = update_device_password(ip, username, old_password, old_enable_secret, new_password, old_enable_secret)
    elif new_enable_secret:
        success = update_device_secret(ip, username, old_password, old_enable_secret, new_enable_secret)
    else:
        print(Style.BRIGHT + "No changes to credentials")
        return
    if success:
        print(Style.BRIGHT + "Credentials updated successfully!")
        save_credentials(ip, username, devicename, new_password or old_password, new_enable_secret or old_enable_secret, device_category)
    else:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "Failed to update the credentials on the device.")

def save_credentials(ip, username, devicename, password, enable_secret, device_category):
    generate_key()
    key = load_key()
    credentials = {}
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            encrypted_content = file.read()
            decrypted_content = decrypt_data(encrypted_content, key)
            credentials = json.loads(decrypted_content)
    credentials[ip] = {
        "devicename": devicename,
        "device_category": device_category,
        "username": username,
        "password": password,
        "enable_secret": enable_secret,
    }
    encrypted_content = encrypt_data(json.dumps(credentials, indent=4), key)
    with open(CREDENTIALS_FILE, "w") as file:
        file.write(encrypted_content)
    print(Style.BRIGHT + f"Credentials for {devicename} ({ip}) saved successfully.")

def list_devices():
    if not os.path.exists(CREDENTIALS_FILE):
        print(Style.BRIGHT + Fore.LIGHTRED_EX + "No credentials file found.")
        return []
    key = load_key()
    with open(CREDENTIALS_FILE, "r") as file:
        encrypted_content = file.read()
        decrypted_content = decrypt_data(encrypted_content, key)
        credentials = json.loads(decrypted_content)
    device_list = []
    for ip, details in credentials.items():
        device_list.append({
            "ip": ip,
            "devicename": details.get("devicename", "Unknown"),
            "device_category": details.get("device_category", "Unknown")
        })
    return device_list

def get_device_credentials(identifier):
    if not os.path.exists(CREDENTIALS_FILE):
        return []

    key = load_key()
    with open(CREDENTIALS_FILE, "r") as file:
        encrypted_content = file.read()
        decrypted_content = decrypt_data(encrypted_content, key)
        credentials = json.loads(decrypted_content)

    result = []
    for ip, details in credentials.items():
        if ip == identifier or details.get("devicename") == identifier:
            result.append({
                "ip": ip,
                "devicename": details.get("devicename", "Unknown"),
                "device_category": details.get("device_category", "Unknown"),
                "username": details.get("username", ""),
                "password": details.get("password", ""),
                "enable_secret": details.get("enable_secret", ""),
            })
    return result

def remove_device(ip):
    if not os.path.exists(CREDENTIALS_FILE):
        print(Style.BRIGHT + Fore.LIGHTRED_EX +"No credentials file found.")
        return

    key = load_key()
    with open(CREDENTIALS_FILE, "r") as file:
        encrypted_content = file.read()
        decrypted_content = decrypt_data(encrypted_content, key)
        credentials = json.loads(decrypted_content)

    if ip in credentials:
        del credentials[ip]
        encrypted_content = encrypt_data(json.dumps(credentials, indent=4), key)
        with open(CREDENTIALS_FILE, "w") as file:
            file.write(encrypted_content)


if __name__ == "__main__":
    while True:
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX  + "\nNetwork Connection Manager")
        print(Style.BRIGHT + "[1] Add Device")
        print(Style.BRIGHT + "[2] Show Devices")
        print(Style.BRIGHT + "[3] Remove Device")
        print(Style.BRIGHT + "[4] Go back to Main Menu")
        choice = input(Style.BRIGHT + Fore.GREEN + "Select an option: ")

        if choice == "1":
            device_category = input(Style.BRIGHT + Fore.GREEN + "Enter device category (router, switch, firewall, server): ").lower()
            if not validate_device_category(device_category):
                continue

            ip = input(Style.BRIGHT + Fore.GREEN + "Enter device IP: ")
            if not validate_ip(ip):
                continue

            devicename = input(Style.BRIGHT + Fore.GREEN + "Enter device name: ")
            if not validate_device_name(devicename):
                continue

            username = input(Style.BRIGHT + Fore.GREEN + "Enter username: ")
            if not validate_username(username):
                continue

            old_password = input(Style.BRIGHT + Fore.GREEN + "Enter current SSH password: ")
            old_enable_secret = input(Style.BRIGHT + Fore.GREEN + "Enter current enable secret: ")

            if len(old_password) < 8 or len(old_enable_secret) < 8:
                prompt_for_new_credentials(ip, username, devicename, old_password, old_enable_secret, device_category)
            else:
                save_credentials(ip, username, devicename, old_password, old_enable_secret, device_category)

        elif choice == "2":
            devices = list_devices()
            if devices:
                print(Style.BRIGHT + "Available devices:")
                for device in devices:
                    print(device)
            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "No devices found.")
                
        elif choice == "3":
            ip = input(Style.BRIGHT + Fore.GREEN + "Enter the IP of the device to remove: ")
            remove_device(ip)        

        elif choice == "4":
            print(Fore.YELLOW + Style.BRIGHT + "Exiting...")
            break

        else:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "Invalid choice. Please try again.")