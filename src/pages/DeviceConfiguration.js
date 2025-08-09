import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import Terminal from '../components/Terminal';
import ConfigurationModal from '../components/ConfigurationModal';
import { Settings, Play, Download } from 'lucide-react';
import pythonBridge from '../utils/pythonBridge';

const DeviceConfiguration = () => {
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedControls, setSelectedControls] = useState([]);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState('retrieve'); // 'retrieve' or 'configure'
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [currentControl, setCurrentControl] = useState(null);
  const [parsedData, setParsedData] = useState(null);

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
      try {
        const deviceList = await pythonBridge.getDevices();
        setDevices(deviceList);
      } catch (error) {
        console.error('Error loading devices:', error);
        setDevices([]);
        if (error.message.includes('Electron environment')) {
          alert('This application must be run in Electron environment for device configuration');
        }
      }
    } catch (error) {
      console.error('Error loading devices:', error);
    }
  };

  const handleControlToggle = (controlId) => {
    if (mode === 'configure') {
      // For configure mode, show modal for controls that need parameters
      const control = configureControls.find(c => c.id === controlId);
      const requiresConfig = ['3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16'].includes(controlId);
      
      if (requiresConfig) {
        setCurrentControl(control);
        setShowConfigModal(true);
      } else {
        // For controls that don't need configuration, toggle directly
        setSelectedControls(prev => 
          prev.includes(controlId) 
            ? prev.filter(id => id !== controlId)
            : [...prev, controlId]
        );
      }
    } else {
      // For retrieve mode, toggle directly
      setSelectedControls(prev => 
        prev.includes(controlId) 
          ? prev.filter(id => id !== controlId)
          : [...prev, controlId]
      );
    }
  };

  const handleConfigSubmit = (configData) => {
    if (currentControl) {
      // Add the control with its configuration data
      setSelectedControls(prev => {
        const newControls = prev.filter(id => id !== currentControl.id);
        return [...newControls, currentControl.id];
      });
      
      // Store configuration data for this control
      setCurrentControl(prev => ({ ...prev, configData }));
    }
    setShowConfigModal(false);
  };

  const executeConfiguration = async () => {
    if (!selectedDevice || selectedControls.length === 0) {
      alert('Please select a device and at least one control');
      return;
    }

    try {
      setLoading(true);
      setOutput('Starting configuration...\n');
      setParsedData(null);

      const scriptPath = mode === 'retrieve' 
        ? 'device_config/network_configuration_manager.py'
        : 'device_config/device_control.py';

      // Prepare arguments including configuration data
      const args = [selectedDevice, selectedControls.join(',')];
      
      // Add configuration data if in configure mode
      if (mode === 'configure' && currentControl && currentControl.configData) {
        args.push(JSON.stringify(currentControl.configData));
      }

      const result = await pythonBridge.executeScript(scriptPath, args);

      if (result.success) {
        setOutput(pythonBridge.formatOutput(result.output, result.parsedData));
        setParsedData(result.parsedData);
      } else {
        setOutput(prev => prev + `Error: ${result.error}\n`);
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
      const result = await pythonBridge.executeScript(
        'device_config/network_configuration_manager.py', 
        [selectedDevice, 'generate_report']
      );

      if (result.success) {
        setOutput(prev => prev + 'Report generated successfully!\n' + result.output);
      } else {
        setOutput(prev => prev + `Error generating report: ${result.error}\n`);
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
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Device Configuration</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">Retrieve or configure device settings</p>
        </div>
      </div>

      {/* Mode Selection */}
      <Card title="Configuration Mode">
        <div className="flex space-x-4">
          <Button
            variant={mode === 'retrieve' ? 'primary' : 'outline'}
            onClick={() => {
              setMode('retrieve');
              setSelectedControls([]);
              setCurrentControl(null);
            }}
          >
            Configuration Retrieve
          </Button>
          <Button
            variant={mode === 'configure' ? 'primary' : 'outline'}
            onClick={() => {
              setMode('configure');
              setSelectedControls([]);
              setCurrentControl(null);
            }}
          >
            Configuration Set
          </Button>
        </div>
      </Card>

      {/* Device Selection */}
      <Card title="Device Selection">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Select Device
            </label>
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
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
                  ? 'border-blue-500 bg-blue-50 dark:border-dark-orange dark:bg-dark-orange/10'
                  : 'border-gray-200 dark:border-dark-accent hover:border-gray-300 dark:hover:border-dark-orange/50'
              }`}
              onClick={() => handleControlToggle(control.id)}
            >
              <div className="flex items-start space-x-3">
                <input
                  type="checkbox"
                  checked={selectedControls.includes(control.id)}
                  onChange={() => handleControlToggle(control.id)}
                  className="mt-1 rounded border-gray-300 dark:border-dark-accent"
                />
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">{control.name}</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{control.description}</p>
                  {mode === 'configure' && ['3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16'].includes(control.id) && (
                    <span className="inline-block mt-2 px-2 py-1 text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 rounded">
                      Requires Configuration
                    </span>
                  )}
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
              setParsedData(null);
              setCurrentControl(null);
            }}
            variant="outline"
          >
            Clear Selection
          </Button>
        </div>
      </Card>

      {/* Configuration Modal */}
      <ConfigurationModal
        isOpen={showConfigModal}
        onClose={() => setShowConfigModal(false)}
        onSubmit={handleConfigSubmit}
        control={currentControl}
        loading={loading}
      />

      {/* Output Terminal */}
      <Card title="Output">
        <Terminal output={output} isLoading={loading} parsedData={parsedData} />
      </Card>
    </div>
  );
};

export default DeviceConfiguration;