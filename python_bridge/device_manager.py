#!/usr/bin/env python3
import sys
import os
import json

# Add the parent directory to sys.path to import from the main application
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connection_management.encrypted_connections import (
    list_devices, 
    save_credentials, 
    get_device_credentials,
    remove_device
)

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command specified"}))
        return

    command = sys.argv[1]

    try:
        if command == "list_devices":
            devices = list_devices()
            print(json.dumps(devices))
        
        elif command == "save_device":
            if len(sys.argv) < 3:
                print(json.dumps({"error": "No device data provided"}))
                return
            
            device_data = json.loads(sys.argv[2])
            save_credentials(
                device_data['ip'],
                device_data['username'],
                device_data['devicename'],
                device_data['password'],
                device_data['enable_secret'],
                device_data['device_category']
            )
            print(json.dumps({"success": True, "message": "Device saved successfully"}))
        
        elif command == "get_device":
            if len(sys.argv) < 3:
                print(json.dumps({"error": "No device identifier provided"}))
                return
            
            identifier = sys.argv[2]
            credentials = get_device_credentials(identifier)
            print(json.dumps(credentials))
        
        elif command == "remove_device":
            if len(sys.argv) < 3:
                print(json.dumps({"error": "No device IP provided"}))
                return
            
            device_ip = sys.argv[2]
            remove_device(device_ip)
            print(json.dumps({"success": True, "message": "Device removed successfully"}))
        
        else:
            print(json.dumps({"error": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    main()