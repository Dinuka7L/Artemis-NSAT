import paramiko
import threading
import time
import json
import sys
import os
from queue import Queue, Empty
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Add parent directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
sys.path.append(parent_dir)

from connection_management.encrypted_connections import get_device_credentials

class SSHTerminal:
    def __init__(self):
        self.client = None
        self.shell = None
        self.connected = False
        self.output_queue = Queue()
        self.input_queue = Queue()
        self.output_thread = None
        self.input_thread = None
        self.device_info = None
        
    def connect(self, device_identifier, username=None, password=None, enable_secret=None):
        """
        Connect to a device using SSH
        """
        try:
            # Get device credentials if not provided
            if not username or not password:
                credentials = get_device_credentials(device_identifier)
                if not credentials:
                    return {
                        "success": False,
                        "error": f"No credentials found for device: {device_identifier}"
                    }
                
                device_cred = credentials[0]
                username = username or device_cred.get("username")
                password = password or device_cred.get("password")
                enable_secret = enable_secret or device_cred.get("enable_secret")
                device_name = device_cred.get("devicename", device_identifier)
                device_ip = device_cred.get("ip", device_identifier)
            else:
                device_name = device_identifier
                device_ip = device_identifier
            
            # Store device info
            self.device_info = {
                "name": device_name,
                "ip": device_ip,
                "username": username,
                "enable_secret": enable_secret
            }
            
            # Create SSH client
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to device
            self.client.connect(
                hostname=device_ip,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Create interactive shell
            self.shell = self.client.invoke_shell(
                term='vt100',
                width=80,
                height=24
            )
            
            # Set shell timeout
            self.shell.settimeout(0.1)
            
            self.connected = True
            
            # Start output monitoring thread
            self.output_thread = threading.Thread(target=self._monitor_output, daemon=True)
            self.output_thread.start()
            
            # Start input processing thread
            self.input_thread = threading.Thread(target=self._process_input, daemon=True)
            self.input_thread.start()
            
            # Wait a moment for initial output
            time.sleep(1)
            
            return {
                "success": True,
                "message": f"Connected to {device_name} ({device_ip})",
                "device_info": self.device_info
            }
            
        except paramiko.AuthenticationException:
            return {
                "success": False,
                "error": "Authentication failed. Please check username and password."
            }
        except paramiko.SSHException as e:
            return {
                "success": False,
                "error": f"SSH connection failed: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Connection failed: {str(e)}"
            }
    
    def _monitor_output(self):
        """
        Monitor SSH shell output in a separate thread
        """
        buffer = ""
        while self.connected and self.shell:
            try:
                if self.shell.recv_ready():
                    data = self.shell.recv(1024).decode('utf-8', errors='ignore')
                    buffer += data
                    
                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        self.output_queue.put({
                            "type": "output",
                            "data": line + '\n',
                            "timestamp": time.time()
                        })
                    
                    # If buffer is getting too long without newline, flush it
                    if len(buffer) > 1000:
                        self.output_queue.put({
                            "type": "output",
                            "data": buffer,
                            "timestamp": time.time()
                        })
                        buffer = ""
                        
                time.sleep(0.01)  # Small delay to prevent high CPU usage
                
            except Exception as e:
                if self.connected:
                    self.output_queue.put({
                        "type": "error",
                        "data": f"Output monitoring error: {str(e)}\n",
                        "timestamp": time.time()
                    })
                break
    
    def _process_input(self):
        """
        Process input commands in a separate thread
        """
        while self.connected and self.shell:
            try:
                command = self.input_queue.get(timeout=0.1)
                if command and self.shell:
                    self.shell.send(command + '\n')
                    
                    # Add command echo to output
                    self.output_queue.put({
                        "type": "command",
                        "data": command + '\n',
                        "timestamp": time.time()
                    })
                    
            except Empty:
                continue
            except Exception as e:
                if self.connected:
                    self.output_queue.put({
                        "type": "error",
                        "data": f"Input processing error: {str(e)}\n",
                        "timestamp": time.time()
                    })
                break
    
    def send_command(self, command):
        """
        Send a command to the SSH shell
        """
        if not self.connected or not self.shell:
            return {
                "success": False,
                "error": "Not connected to device"
            }
        
        try:
            self.input_queue.put(command)
            return {
                "success": True,
                "message": f"Command sent: {command}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send command: {str(e)}"
            }
    
    def get_output(self):
        """
        Get accumulated output from the shell
        """
        output_data = []
        
        try:
            while True:
                try:
                    item = self.output_queue.get_nowait()
                    output_data.append(item)
                except Empty:
                    break
        except Exception as e:
            output_data.append({
                "type": "error",
                "data": f"Error getting output: {str(e)}\n",
                "timestamp": time.time()
            })
        
        return output_data
    
    def enable_mode(self):
        """
        Enter privileged EXEC mode
        """
        if not self.connected or not self.device_info.get("enable_secret"):
            return {
                "success": False,
                "error": "Not connected or no enable secret available"
            }
        
        try:
            self.send_command("enable")
            time.sleep(0.5)
            self.send_command(self.device_info["enable_secret"])
            
            return {
                "success": True,
                "message": "Entered privileged EXEC mode"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to enter enable mode: {str(e)}"
            }
    
    def disconnect(self):
        """
        Disconnect from the SSH session
        """
        try:
            self.connected = False
            
            if self.shell:
                self.shell.close()
                self.shell = None
            
            if self.client:
                self.client.close()
                self.client = None
            
            # Clear queues
            while not self.output_queue.empty():
                try:
                    self.output_queue.get_nowait()
                except Empty:
                    break
            
            while not self.input_queue.empty():
                try:
                    self.input_queue.get_nowait()
                except Empty:
                    break
            
            return {
                "success": True,
                "message": "Disconnected successfully"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Error during disconnect: {str(e)}"
            }
    
    def get_status(self):
        """
        Get current connection status
        """
        return {
            "connected": self.connected,
            "device_info": self.device_info if self.connected else None,
            "shell_active": self.shell is not None if self.connected else False
        }

# Global terminal instance
terminal_instance = SSHTerminal()

def main():
    """
    Main function for command-line usage
    """
    if len(sys.argv) < 2:
        print("Usage: python ssh_terminal.py <command> [args...]")
        print("Commands:")
        print("  connect <device_ip_or_name> [username] [password] [enable_secret]")
        print("  send <command>")
        print("  enable")
        print("  output")
        print("  status")
        print("  disconnect")
        return
    
    command = sys.argv[1].lower()
    
    if command == "connect":
        if len(sys.argv) < 3:
            print("Error: Device IP or name required")
            return
        
        device = sys.argv[2]
        username = sys.argv[3] if len(sys.argv) > 3 else None
        password = sys.argv[4] if len(sys.argv) > 4 else None
        enable_secret = sys.argv[5] if len(sys.argv) > 5 else None
        
        result = terminal_instance.connect(device, username, password, enable_secret)
        print(json.dumps(result, indent=2))
    
    elif command == "send":
        if len(sys.argv) < 3:
            print("Error: Command required")
            return
        
        cmd = " ".join(sys.argv[2:])
        result = terminal_instance.send_command(cmd)
        print(json.dumps(result, indent=2))
    
    elif command == "enable":
        result = terminal_instance.enable_mode()
        print(json.dumps(result, indent=2))
    
    elif command == "output":
        output_data = terminal_instance.get_output()
        for item in output_data:
            print(f"[{item['type']}] {item['data']}", end='')
    
    elif command == "status":
        status = terminal_instance.get_status()
        print(json.dumps(status, indent=2))
    
    elif command == "disconnect":
        result = terminal_instance.disconnect()
        print(json.dumps(result, indent=2))
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()