import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Button from '../components/Button';
import { 
  Terminal as TerminalIcon, 
  Power, 
  PowerOff, 
  Send, 
  Trash2, 
  Settings,
  Shield,
  Network,
  Eye,
  EyeOff
} from 'lucide-react';
import pythonBridge from '../utils/pythonBridge';

const Terminal = () => {
  const navigate = useNavigate();
  const terminalRef = useRef(null);
  const inputRef = useRef(null);
  
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [connected, setConnected] = useState(false);
  const [connectionInfo, setConnectionInfo] = useState(null);
  const [terminalOutput, setTerminalOutput] = useState([]);
  const [currentCommand, setCurrentCommand] = useState('');
  const [loading, setLoading] = useState(false);
  const [showCredentials, setShowCredentials] = useState(false);
  const [customCredentials, setCustomCredentials] = useState({
    username: '',
    password: '',
    enable_secret: ''
  });

  useEffect(() => {
    loadDevices();
    // Auto-scroll terminal to bottom when new output is added
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalOutput]);

  useEffect(() => {
    // Poll for output when connected
    let interval;
    if (connected) {
      interval = setInterval(async () => {
        try {
          const result = await pythonBridge.executeTerminalAction('get_output');
          if (result.success && result.output && result.output.length > 0) {
            setTerminalOutput(prev => [...prev, ...result.output]);
          }
        } catch (error) {
          console.error('Error polling terminal output:', error);
        }
      }, 500); // Poll every 500ms
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [connected]);

  const loadDevices = async () => {
    try {
      const deviceList = await pythonBridge.getDevices();
      setDevices(deviceList);
    } catch (error) {
      console.error('Error loading devices:', error);
      setDevices([]);
    }
  };

  const connectToDevice = async () => {
    if (!selectedDevice) {
      alert('Please select a device');
      return;
    }

    try {
      setLoading(true);
      addToTerminal('system', `Connecting to ${selectedDevice}...`);

      const params = { device: selectedDevice };
      
      // Add custom credentials if provided
      if (showCredentials) {
        if (customCredentials.username) params.username = customCredentials.username;
        if (customCredentials.password) params.password = customCredentials.password;
        if (customCredentials.enable_secret) params.enable_secret = customCredentials.enable_secret;
      }

      const result = await pythonBridge.executeTerminalAction('connect', params);
      
      if (result.success) {
        setConnected(true);
        setConnectionInfo(result.device_info);
        addToTerminal('system', `✓ Connected to ${result.device_info?.name || selectedDevice}`);
        addToTerminal('system', `Device: ${result.device_info?.name} (${result.device_info?.ip})`);
        addToTerminal('system', 'Type commands below or use quick actions...');
      } else {
        addToTerminal('error', `✗ Connection failed: ${result.error}`);
      }
    } catch (error) {
      addToTerminal('error', `✗ Connection error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const disconnectFromDevice = async () => {
    try {
      setLoading(true);
      addToTerminal('system', 'Disconnecting...');

      const result = await pythonBridge.executeTerminalAction('disconnect');
      
      if (result.success) {
        setConnected(false);
        setConnectionInfo(null);
        addToTerminal('system', '✓ Disconnected successfully');
      } else {
        addToTerminal('error', `✗ Disconnect error: ${result.error}`);
      }
    } catch (error) {
      addToTerminal('error', `✗ Disconnect error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const sendCommand = async (command = currentCommand) => {
    if (!connected || !command.trim()) return;

    try {
      addToTerminal('command', command);
      setCurrentCommand('');

      const result = await pythonBridge.executeTerminalAction('send_command', { command });
      
      if (!result.success) {
        addToTerminal('error', `Command error: ${result.error}`);
      }
    } catch (error) {
      addToTerminal('error', `Command error: ${error.message}`);
    }
  };

  const enterEnableMode = async () => {
    if (!connected) return;

    try {
      addToTerminal('system', 'Entering privileged EXEC mode...');
      const result = await pythonBridge.executeTerminalAction('enable');
      
      if (result.success) {
        addToTerminal('system', '✓ Entered privileged EXEC mode');
      } else {
        addToTerminal('error', `✗ Enable mode error: ${result.error}`);
      }
    } catch (error) {
      addToTerminal('error', `✗ Enable mode error: ${error.message}`);
    }
  };

  const addToTerminal = (type, data) => {
    const timestamp = new Date().toLocaleTimeString();
    setTerminalOutput(prev => [...prev, {
      type,
      data,
      timestamp: Date.now(),
      time: timestamp
    }]);
  };

  const clearTerminal = () => {
    setTerminalOutput([]);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      sendCommand();
    }
  };

  const quickCommands = [
    { label: 'Show Version', command: 'show version' },
    { label: 'Show Running Config', command: 'show running-config' },
    { label: 'Show Interfaces', command: 'show ip interface brief' },
    { label: 'Show Routes', command: 'show ip route' },
    { label: 'Show VLANs', command: 'show vlan brief' },
    { label: 'Show CDP Neighbors', command: 'show cdp neighbors' },
    { label: 'Show MAC Table', command: 'show mac address-table' },
    { label: 'Show Logs', command: 'show logging' }
  ];

  const getOutputClass = (type) => {
    switch (type) {
      case 'command': return 'text-cyan-400 font-semibold';
      case 'error': return 'text-red-400';
      case 'system': return 'text-green-400';
      case 'output': return 'text-gray-300';
      default: return 'text-gray-300';
    }
  };

  const selectedDeviceInfo = devices.find(d => d.ip === selectedDevice);

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Terminal Interface</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Interactive SSH terminal for direct device communication
          </p>
        </div>
        <div className="flex items-center space-x-2">
          {connected && connectionInfo && (
            <div className="flex items-center space-x-2 px-3 py-2 bg-green-100 dark:bg-green-900 rounded-lg">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-green-800 dark:text-green-200 text-sm font-medium">
                Connected to {connectionInfo.name}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Connection Panel */}
      <Card title="Device Connection" className="border-l-4 border-l-orange-600 dark:border-l-orange-500">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Select Device
              </label>
              <select
                value={selectedDevice}
                onChange={(e) => setSelectedDevice(e.target.value)}
                disabled={connected}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 dark:focus:ring-orange-400 bg-white dark:bg-gray-800 text-gray-900 dark:text-white disabled:opacity-50"
              >
                <option value="">Choose a device...</option>
                {devices.map((device, index) => (
                  <option key={index} value={device.ip}>
                    {device.devicename} ({device.ip}) - {device.device_category}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-end space-x-2">
              <Button
                onClick={showCredentials ? () => setShowCredentials(false) : () => setShowCredentials(true)}
                variant="outline"
                size="sm"
                className="flex items-center space-x-2"
              >
                {showCredentials ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                <span>Custom Credentials</span>
              </Button>
              
              {!connected ? (
                <Button
                  onClick={connectToDevice}
                  loading={loading}
                  disabled={!selectedDevice}
                  className="flex items-center space-x-2"
                >
                  <Power className="w-4 h-4" />
                  <span>Connect</span>
                </Button>
              ) : (
                <Button
                  onClick={disconnectFromDevice}
                  loading={loading}
                  variant="danger"
                  className="flex items-center space-x-2"
                >
                  <PowerOff className="w-4 h-4" />
                  <span>Disconnect</span>
                </Button>
              )}
            </div>
          </div>

          {/* Custom Credentials */}
          {showCredentials && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Username (optional)
                </label>
                <input
                  type="text"
                  value={customCredentials.username}
                  onChange={(e) => setCustomCredentials(prev => ({...prev, username: e.target.value}))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 dark:focus:ring-orange-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="admin"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Password (optional)
                </label>
                <input
                  type="password"
                  value={customCredentials.password}
                  onChange={(e) => setCustomCredentials(prev => ({...prev, password: e.target.value}))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 dark:focus:ring-orange-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="••••••••"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Enable Secret (optional)
                </label>
                <input
                  type="password"
                  value={customCredentials.enable_secret}
                  onChange={(e) => setCustomCredentials(prev => ({...prev, enable_secret: e.target.value}))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 dark:focus:ring-orange-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="••••••••"
                />
              </div>
            </div>
          )}

          {/* Device Info */}
          {selectedDeviceInfo && (
            <div className="p-4 bg-blue-50 dark:bg-blue-900 rounded-lg">
              <div className="flex items-center space-x-3">
                <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <div>
                  <h4 className="font-medium text-blue-900 dark:text-blue-200">
                    {selectedDeviceInfo.devicename}
                  </h4>
                  <p className="text-sm text-blue-700 dark:text-blue-300">
                    {selectedDeviceInfo.ip} • {selectedDeviceInfo.device_category}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Quick Actions */}
      {connected && (
        <Card title="Quick Actions">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Button
              onClick={enterEnableMode}
              variant="warning"
              size="sm"
              className="flex items-center space-x-2"
            >
              <Shield className="w-4 h-4" />
              <span>Enable Mode</span>
            </Button>
            
            {quickCommands.slice(0, 7).map((cmd, index) => (
              <Button
                key={index}
                onClick={() => sendCommand(cmd.command)}
                variant="outline"
                size="sm"
                className="text-xs"
              >
                {cmd.label}
              </Button>
            ))}
          </div>
        </Card>
      )}

      {/* Terminal */}
      <Card title="Terminal Output" className="border-l-4 border-l-green-600 dark:border-l-green-500">
        <div className="space-y-4">
          {/* Terminal Output */}
          <div
            ref={terminalRef}
            className="bg-gray-900 dark:bg-black text-green-400 dark:text-green-300 font-mono text-sm p-4 rounded-lg h-96 overflow-y-auto border border-gray-700 dark:border-gray-600"
          >
            {terminalOutput.length === 0 ? (
              <div className="text-gray-500 dark:text-gray-400 italic">
                Terminal ready. Connect to a device to start...
              </div>
            ) : (
              terminalOutput.map((item, index) => (
                <div key={index} className="mb-1">
                  <span className="text-gray-500 text-xs mr-2">[{item.time}]</span>
                  <span className={getOutputClass(item.type)}>
                    {item.type === 'command' && '$ '}
                    {item.data}
                  </span>
                </div>
              ))
            )}
          </div>

          {/* Command Input */}
          <div className="flex space-x-2">
            <div className="flex-1 relative">
              <input
                ref={inputRef}
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={!connected}
                className="w-full px-3 py-2 pl-8 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 dark:focus:ring-orange-400 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono disabled:opacity-50"
                placeholder={connected ? "Enter command..." : "Connect to device first"}
              />
              <TerminalIcon className="w-4 h-4 text-gray-400 absolute left-2 top-3" />
            </div>
            
            <Button
              onClick={() => sendCommand()}
              disabled={!connected || !currentCommand.trim()}
              className="flex items-center space-x-2"
            >
              <Send className="w-4 h-4" />
              <span>Send</span>
            </Button>
            
            <Button
              onClick={clearTerminal}
              variant="outline"
              className="flex items-center space-x-2"
            >
              <Trash2 className="w-4 h-4" />
              <span>Clear</span>
            </Button>
          </div>

          {/* Connection Status */}
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
                <span className="text-gray-600 dark:text-gray-400">
                  {connected ? 'Connected' : 'Disconnected'}
                </span>
              </div>
              
              {connectionInfo && (
                <span className="text-gray-600 dark:text-gray-400">
                  {connectionInfo.name} ({connectionInfo.ip})
                </span>
              )}
            </div>
            
            <div className="text-gray-500 dark:text-gray-400">
              {terminalOutput.length} lines
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Terminal;