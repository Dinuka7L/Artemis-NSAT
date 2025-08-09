import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import Terminal from '../components/Terminal';
import { Shield, Play, AlertTriangle } from 'lucide-react';
import pythonBridge from '../utils/pythonBridge';

const AttackMitigation = () => {
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedControls, setSelectedControls] = useState([]);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [parsedData, setParsedData] = useState(null);

  const attackMitigationControls = [
    {
      id: '1',
      name: 'Disable Telnet',
      description: 'Prevent unauthorized access by disabling Telnet',
      attack: 'Unauthorized Access',
      severity: 'High',
      color: 'red'
    },
    {
      id: '2',
      name: 'Password Encryption',
      description: 'Encrypt stored passwords to prevent password attacks',
      attack: 'Password Attacks',
      severity: 'High',
      color: 'red'
    },
    {
      id: '3',
      name: 'Enable Secret',
      description: 'Configure enable secret to secure privileged access',
      attack: 'Password Attacks',
      severity: 'High',
      color: 'red'
    },
    {
      id: '4',
      name: 'Port Security',
      description: 'Prevent MAC address overflow attacks',
      attack: 'MAC Address Overflow',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '5',
      name: 'MOTD Banner',
      description: 'Display warning banner to deter unauthorized access',
      attack: 'Unauthorized Access',
      severity: 'Low',
      color: 'blue'
    },
    {
      id: '6',
      name: 'Exec Timeout',
      description: 'Automatically logout idle sessions',
      attack: 'Unauthorized Access',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '7',
      name: 'Syslog Configuration',
      description: 'Enable logging for security monitoring',
      attack: 'Logging',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '8',
      name: 'BPDU Guard',
      description: 'Protect against STP attacks',
      attack: 'STP Attack',
      severity: 'High',
      color: 'red'
    },
    {
      id: '9',
      name: 'Root Guard',
      description: 'Prevent unauthorized root bridge changes',
      attack: 'STP Attack',
      severity: 'High',
      color: 'red'
    },
    {
      id: '10',
      name: 'Shutdown Ports',
      description: 'Disable unused ports to prevent unauthorized access',
      attack: 'Network Misconfigurations',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '11',
      name: 'Activate Ports',
      description: 'Enable required ports',
      attack: 'Network Misconfigurations',
      severity: 'Low',
      color: 'blue'
    },
    {
      id: '12',
      name: 'Disable DTP',
      description: 'Prevent Dynamic Trunking Protocol attacks',
      attack: 'Network Misconfigurations',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '13',
      name: 'Disable CDP',
      description: 'Prevent information disclosure via CDP',
      attack: 'Network Misconfigurations',
      severity: 'Medium',
      color: 'yellow'
    },
    {
      id: '14',
      name: 'DHCP Snooping',
      description: 'Prevent DHCP starvation attacks',
      attack: 'DHCP Starvation',
      severity: 'High',
      color: 'red'
    },
    {
      id: '15',
      name: 'Dynamic ARP Inspection',
      description: 'Protect against ARP spoofing attacks',
      attack: 'Data Integrity',
      severity: 'High',
      color: 'red'
    },
    {
      id: '16',
      name: 'Login Block',
      description: 'Prevent brute-force login attempts',
      attack: 'Brute-force Prevention',
      severity: 'High',
      color: 'red'
    }
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
          alert('This application must be run in Electron environment for attack mitigation');
        }
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

  const executeAttackMitigation = async () => {
    if (!selectedDevice || selectedControls.length === 0) {
      alert('Please select a device and at least one mitigation control');
      return;
    }

    try {
      setLoading(true);
      setOutput('Starting attack mitigation deployment...\n');
      setParsedData(null);

      const result = await pythonBridge.executeScript(
        'device_config/attack_mitigation.py', 
        [selectedDevice, selectedControls.join(',')]
      );

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

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900 dark:text-red-200 dark:border-red-700';
      case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900 dark:text-yellow-200 dark:border-yellow-700';
      case 'Low': return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900 dark:text-blue-200 dark:border-blue-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600';
    }
  };

  const getAttackTypeColor = (attack) => {
    const colors = {
      'Unauthorized Access': 'bg-red-50 text-red-700 dark:bg-red-900 dark:text-red-200',
      'Password Attacks': 'bg-orange-50 text-orange-700 dark:bg-orange-900 dark:text-orange-200',
      'MAC Address Overflow': 'bg-purple-50 text-purple-700 dark:bg-purple-900 dark:text-purple-200',
      'STP Attack': 'bg-pink-50 text-pink-700 dark:bg-pink-900 dark:text-pink-200',
      'Network Misconfigurations': 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200',
      'DHCP Starvation': 'bg-green-50 text-green-700 dark:bg-green-900 dark:text-green-200',
      'Data Integrity': 'bg-indigo-50 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-200',
      'Brute-force Prevention': 'bg-gray-50 text-gray-700 dark:bg-gray-700 dark:text-gray-200',
      'Logging': 'bg-teal-50 text-teal-700 dark:bg-teal-900 dark:text-teal-200'
    };
    return colors[attack] || 'bg-gray-50 text-gray-700 dark:bg-gray-700 dark:text-gray-200';
  };

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Attack Mitigation</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">Deploy security controls to mitigate common network attacks</p>
        </div>
      </div>

      {/* Attack Overview */}
      <Card title="Security Threat Overview" className="border-l-4 border-l-red-500 dark:border-l-dark-orange">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-red-50 dark:bg-red-900 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400 mx-auto mb-2" />
            <h3 className="font-semibold text-red-900 dark:text-red-200">High Severity</h3>
            <p className="text-red-700 dark:text-red-300">
              {attackMitigationControls.filter(c => c.severity === 'High').length} Controls
            </p>
          </div>
          <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-900 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-yellow-600 dark:text-yellow-400 mx-auto mb-2" />
            <h3 className="font-semibold text-yellow-900 dark:text-yellow-200">Medium Severity</h3>
            <p className="text-yellow-700 dark:text-yellow-300">
              {attackMitigationControls.filter(c => c.severity === 'Medium').length} Controls
            </p>
          </div>
          <div className="text-center p-4 bg-blue-50 dark:bg-blue-900 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-blue-600 dark:text-blue-400 mx-auto mb-2" />
            <h3 className="font-semibold text-blue-900 dark:text-blue-200">Low Severity</h3>
            <p className="text-blue-700 dark:text-blue-300">
              {attackMitigationControls.filter(c => c.severity === 'Low').length} Controls
            </p>
          </div>
        </div>
      </Card>

      {/* Device Selection */}
      <Card title="Target Device">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Select Device for Attack Mitigation
          </label>
          <select
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
          >
            <option value="">Choose a device...</option>
            {devices.map((device, index) => (
              <option key={index} value={device.ip}>
                {device.devicename} ({device.ip}) - {device.device_category}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {/* Mitigation Controls */}
      <Card title="Attack Mitigation Controls">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {attackMitigationControls.map((control) => (
            <div
              key={control.id}
              className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                selectedControls.includes(control.id)
                  ? 'border-red-500 bg-red-50 dark:border-dark-orange dark:bg-dark-orange/10'
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
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-gray-900 dark:text-white">{control.name}</h4>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(control.severity)}`}>
                      {control.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{control.description}</p>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-gray-500 dark:text-gray-500">Mitigates:</span>
                    <span className={`px-2 py-1 text-xs font-medium rounded ${getAttackTypeColor(control.attack)}`}>
                      {control.attack}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex space-x-4 mt-6">
          <Button
            onClick={executeAttackMitigation}
            loading={loading}
            disabled={!selectedDevice || selectedControls.length === 0}
            className="flex items-center space-x-2"
          >
            <Shield className="w-4 h-4" />
            <span>Deploy Mitigations</span>
          </Button>

          <Button
            onClick={() => {
              setSelectedControls([]);
              setOutput('');
              setParsedData(null);
            }}
            variant="outline"
          >
            Clear Selection
          </Button>

          <Button
            onClick={() => {
              const highSeverityControls = attackMitigationControls
                .filter(c => c.severity === 'High')
                .map(c => c.id);
              setSelectedControls(highSeverityControls);
            }}
            variant="warning"
          >
            Select High Priority
          </Button>
        </div>
      </Card>

      {/* Output Terminal */}
      <Card title="Deployment Output">
        <Terminal output={output} isLoading={loading} parsedData={parsedData} />
      </Card>
    </div>
  );
};

export default AttackMitigation;