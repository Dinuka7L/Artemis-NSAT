import json
import sys
import os
from ssh_terminal import terminal_instance

# Add parent directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
sys.path.append(parent_dir)

def handle_terminal_request(action, params=None):
    """
    Handle terminal requests from the GUI
    """
    if params is None:
        params = {}
    
    try:
        if action == "connect":
            device = params.get("device")
            username = params.get("username")
            password = params.get("password")
            enable_secret = params.get("enable_secret")
            
            if not device:
                return {
                    "success": False,
                    "error": "Device identifier required"
                }
            
            result = terminal_instance.connect(device, username, password, enable_secret)
            return result
        
        elif action == "send_command":
            command = params.get("command", "")
            result = terminal_instance.send_command(command)
            return result
        
        elif action == "get_output":
            output_data = terminal_instance.get_output()
            return {
                "success": True,
                "output": output_data
            }
        
        elif action == "enable":
            result = terminal_instance.enable_mode()
            return result
        
        elif action == "disconnect":
            result = terminal_instance.disconnect()
            return result
        
        elif action == "status":
            status = terminal_instance.get_status()
            return {
                "success": True,
                "status": status
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Terminal manager error: {str(e)}"
        }

def main():
    """
    Main function for GUI bridge
    """
    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "error": "Action required"
        }))
        return
    
    action = sys.argv[1]
    params = {}
    
    # Parse parameters from command line arguments
    if len(sys.argv) > 2:
        try:
            params = json.loads(sys.argv[2])
        except json.JSONDecodeError:
            # If not JSON, treat as simple parameters
            if action == "connect" and len(sys.argv) >= 3:
                params["device"] = sys.argv[2]
                if len(sys.argv) >= 4:
                    params["username"] = sys.argv[3]
                if len(sys.argv) >= 5:
                    params["password"] = sys.argv[4]
                if len(sys.argv) >= 6:
                    params["enable_secret"] = sys.argv[5]
            elif action == "send_command" and len(sys.argv) >= 3:
                params["command"] = " ".join(sys.argv[2:])
    
    result = handle_terminal_request(action, params)
    print(json.dumps(result))

if __name__ == "__main__":
    main()