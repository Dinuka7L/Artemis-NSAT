import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import Terminal from '../components/Terminal';
import { Settings, Play, Download } from 'lucide-react';

const ipcRenderer = window.require ? window.require('electron').ipcRenderer : null;

const DeviceConfiguration = () => {
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedControls, setSelectedControls] = useState([]);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState('retrieve'); // 'retrieve' or 'configure'

  const retrieveControls = [
    { id: '1', name: 'Telnet Status', description: 'Check if Telnet is enabled' },
    { id: '2', name: 'SSH Status', description: 'Check if SSH v2 is enabled' },
    { id: '3', name: 'Password Encryption', description: 'Check password encryption status' },
    { id: '4', name: 'Enable Secret', description: 'Check privilege exec password' },
    { id: '5', name: 'IOS Version', description: 'Check Cisco IOS version' },
    { id: '6', name: 'MOTD Banner', description: 'Check Message of the Day banner' },
    { id: '7', name: 'Syslog Configuration', description: 'Check logging configuration' },
    { id: '8', name: 'Exec Timeout', description: 'Check remote login timeout settings' },
    { id: '9', name: 'Port Security', description: 'Check port security on all interfaces' },
    { id: '10', name: 'BPDU Guard', description: 'Check BPDU Guard configuration' },
    { id: '11', name: 'Root Guard', description: 'Check Root Guard configuration' },
    { id: '12', name: 'Shutdown Ports', description: 'Check administratively shutdown ports' },
    { id: '13', name: 'Active Ports', description: 'Check active ports' },
    { id: '14', name: 'DTP Configuration', description: 'Check DTP nonegotiate ports' },
    { id: '15', name: 'CDP Configuration', description: 'Check CDP disabled ports' },
    { id: '16', name: 'DHCP Snooping', description: 'Check DHCP snooping status' },
    { id: '17', name: 'ARP Inspection', description: 'Check Dynamic ARP Inspection' },
    { id: '18', name: 'Login Fail Lock', description: 'Check login fail lock status' }
  ];

  const configureControls = [
    { id: '1', name: 'Disable Telnet', description: 'Disable Telnet access' },
    { id: '2', name: 'Enable Password Encryption', description: 'Enable service password-encryption' },
    { id: '3', name: 'Configure Enable Secret', description: 'Set enable secret password' },
    { id: '4', name: 'Configure Port Security', description: 'Enable port security on interfaces' },
    { id: '5', name: 'Configure MOTD Banner', description: 'Set Message of the Day banner' },
    { id: '6', name: 'Configure Exec Timeout', description: 'Set remote login timeout' },
    { id: '7', name: 'Configure Syslog', description: 'Configure syslog server' },
    { id: '8', name: 'Configure BPDU Guard', description: 'Enable BPDU Guard on interfaces' },
    { id: '9', name: 'Configure Root Guard', description: 'Enable Root Guard on interfaces' },
    { id: '10', name: 'Shutdown Ports', description: 'Administratively shutdown ports' },
    { id: '11', name: 'Activate Ports', description: 'Activate ports (no shutdown)' },
    { id: '12', name: 'Disable DTP', description: 'Disable Dynamic Trunking Protocol' },
    { id: '13', name: 'Disable CDP', description: 'Disable Cisco Discovery Protocol' },
    { id: '14', name: 'Configure DHCP Snooping', description: 'Enable DHCP snooping' },
    { id: '15', name: 'Configure ARP Inspection', description: 'Enable Dynamic ARP Inspection' },
    { id: '16', name: 'Configure Login Block', description: 'Configure login fail lock' }
  ];

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      if (ipcRenderer) {
        const result = await ipcRenderer.invoke('get-devices');
        if (result && !result.error) {
          setDevices(result);
        }
      } else {
        // Mock data for browser environment
        setDevices([
          { devicename: 'Router-1', ip: '192.168.1.1', device_category: 'router' },
          { devicename: 'Switch-1', ip: '192.168.1.2', device_category: 'switch' }
        ]);
      }
    } catch (error) {
      console.error('Error loading devices:', error);
    }
  };

  const handleControlToggle = (controlId) => {
    setSelectedControls(prev => 
      prev.includes(controlId) 
        ? prev.filter(id => id !== controlId)
        : [...prev, controlId]
    );
  };

  const executeConfiguration = async () => {
    if (!selectedDevice || selectedControls.length === 0) {
      alert('Please select a device and at least one control');
      return;
    }

    try {
      setLoading(true);
      setOutput('Starting configuration...\n');

      if (ipcRenderer) {
        const scriptPath = mode === 'retrieve' 
          ? 'device_config/network_configuration_manager.py'
          : 'device_config/device_control.py';

        const result = await ipcRenderer.invoke('execute-python-script', scriptPath, [
          selectedDevice,
          selectedControls.join(',')
        ]);

        if (result.success) {
          setOutput(prev => prev + result.output);
        } else {
          setOutput(prev => prev + `Error: ${result.error}\n`);
        }
      } else {
        // Mock response for browser environment
        setOutput(prev => prev + `Mock: ${mode === 'retrieve' ? 'Configuration retrieval' : 'Configuration application'} would be executed in Electron environment\n`);
      }
    } catch (error) {
      setOutput(prev => prev + `Error: ${error.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    if (!selectedDevice) {
      alert('Please select a device first');
      return;
    }

    try {
      setLoading(true);
      if (ipcRenderer) {
        const result = await ipcRenderer.invoke('execute-python-script', 
          'device_config/network_configuration_manager.py', 
          [selectedDevice, 'generate_report']
        );

        if (result.success) {
          setOutput(prev => prev + 'Report generated successfully!\n' + result.output);
        } else {
          setOutput(prev => prev + `Error generating report: ${result.error}\n`);
        }
      } else {
        // Mock response for browser environment
        setOutput(prev => prev + 'Mock: Report would be generated in Electron environment\n');
      }
    } catch (error) {
      setOutput(prev => prev + `Error: ${error.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const currentControls = mode === 'retrieve' ? retrieveControls : configureControls;

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Device Configuration</h1>
          <p className="text-gray-600 mt-2">Retrieve or configure device settings</p>
        </div>
      </div>

      {/* Mode Selection */}
      <Card title="Configuration Mode">
        <div className="flex space-x-4">
          <Button
            variant={mode === 'retrieve' ? 'primary' : 'outline'}
            onClick={() => setMode('retrieve')}
          >
            Configuration Retrieve
          </Button>
          <Button
            variant={mode === 'configure' ? 'primary' : 'outline'}
            onClick={() => setMode('configure')}
          >
            Configuration Set
          </Button>
        </div>
      </Card>

      {/* Device Selection */}
      <Card title="Device Selection">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Device
            </label>
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Choose a device...</option>
              {devices.map((device, index) => (
                <option key={index} value={device.ip}>
                  {device.devicename} ({device.ip}) - {device.device_category}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Controls Selection */}
      <Card title={`Available ${mode === 'retrieve' ? 'Checks' : 'Configurations'}`}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {currentControls.map((control) => (
            <div
              key={control.id}
              className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                selectedControls.includes(control.id)
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
              onClick={() => handleControlToggle(control.id)}
            >
              <div className="flex items-start space-x-3">
                <input
                  type="checkbox"
                  checked={selectedControls.includes(control.id)}
                  onChange={() => handleControlToggle(control.id)}
                  className="mt-1"
                />
                <div>
                  <h4 className="font-medium text-gray-900">{control.name}</h4>
                  <p className="text-sm text-gray-600 mt-1">{control.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex space-x-4 mt-6">
          <Button
            onClick={executeConfiguration}
            loading={loading}
            disabled={!selectedDevice || selectedControls.length === 0}
            className="flex items-center space-x-2"
          >
            <Play className="w-4 h-4" />
            <span>{mode === 'retrieve' ? 'Retrieve Configuration' : 'Apply Configuration'}</span>
          </Button>

          {mode === 'retrieve' && (
            <Button
              onClick={generateReport}
              variant="secondary"
              disabled={!selectedDevice}
              className="flex items-center space-x-2"
            >
              <Download className="w-4 h-4" />
              <span>Generate Report</span>
            </Button>
          )}

          <Button
            onClick={() => {
              setSelectedControls([]);
              setOutput('');
            }}
            variant="outline"
          >
            Clear Selection
          </Button>
        </div>
      </Card>

      {/* Output Terminal */}
      <Card title="Output">
        <Terminal output={output} isLoading={loading} />
      </Card>
    </div>
  );
};

export default DeviceConfiguration;