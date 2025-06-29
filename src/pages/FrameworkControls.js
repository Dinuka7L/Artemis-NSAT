import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import Terminal from '../components/Terminal';
import { AlertTriangle, Play, BookOpen } from 'lucide-react';

const { ipcRenderer } = window.require('electron');

const FrameworkControls = () => {
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedControl, setSelectedControl] = useState('');
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);

  const frameworkControls = [
    {
      id: 'AC-6-3',
      name: 'Network Access to Privileged Commands',
      framework: 'NIST SP 800-53',
      description: 'Restrict network access to privileged commands and functions',
      controls: ['Enable Secret', 'Disable Telnet'],
      category: 'Access Control'
    },
    {
      id: 'AC-6-5',
      name: 'Privileged Account Use Restrictions',
      framework: 'NIST SP 800-53',
      description: 'Restrict privileged account use and implement additional safeguards',
      controls: ['Password Encryption', 'Login Block'],
      category: 'Access Control'
    },
    {
      id: 'AC-7',
      name: 'Unsuccessful Logon Attempts',
      framework: 'NIST SP 800-53',
      description: 'Enforce limits on consecutive invalid logon attempts',
      controls: ['Login Block'],
      category: 'Access Control'
    },
    {
      id: 'CP-9',
      name: 'Information System Backup',
      framework: 'NIST SP 800-53',
      description: 'Conduct backups of system-level information',
      controls: ['Syslog Configuration'],
      category: 'Contingency Planning'
    },
    {
      id: '4.3',
      name: 'Configure Automatic Session Lock',
      framework: 'CIS Controls',
      description: 'Configure automatic session lock after period of inactivity',
      controls: ['Exec Timeout'],
      category: 'Access Control'
    },
    {
      id: '12.3',
      name: 'Securely Manage Network Infrastructure (SSH V2)',
      framework: 'CIS Controls',
      description: 'Securely manage network infrastructure using SSH version 2',
      controls: ['Disable Telnet'],
      category: 'Network Security'
    },
    {
      id: '13.9',
      name: 'Deploy Port-Level Access Control',
      framework: 'CIS Controls',
      description: 'Deploy port-level access control for network infrastructure',
      controls: ['Port Security', 'Shutdown Ports'],
      category: 'Network Security'
    },
    {
      id: 'DTP-DISABLE',
      name: 'Disable Dynamic Trunking Protocol (DTP)',
      framework: 'Industry Best Practice',
      description: 'Disable DTP to prevent VLAN hopping attacks',
      controls: ['Disable DTP'],
      category: 'Network Security'
    },
    {
      id: 'CDP-DISABLE',
      name: 'Disable Cisco Discovery Protocol (CDP)',
      framework: 'Industry Best Practice',
      description: 'Disable CDP to prevent information disclosure',
      controls: ['Disable CDP'],
      category: 'Network Security'
    },
    {
      id: 'DHCP-SNOOPING',
      name: 'Enable DHCP Snooping',
      framework: 'Industry Best Practice',
      description: 'Enable DHCP snooping to prevent DHCP attacks',
      controls: ['DHCP Snooping'],
      category: 'Network Security'
    },
    {
      id: 'STP-PROTECTION',
      name: 'Enable BPDU Guard and Root Guard',
      framework: 'Industry Best Practice',
      description: 'Protect Spanning Tree Protocol from attacks',
      controls: ['BPDU Guard', 'Root Guard'],
      category: 'Network Security'
    }
  ];

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      const result = await ipcRenderer.invoke('get-devices');
      if (result && !result.error) {
        setDevices(result);
      }
    } catch (error) {
      console.error('Error loading devices:', error);
    }
  };

  const executeFrameworkControl = async () => {
    if (!selectedDevice || !selectedControl) {
      alert('Please select a device and a framework control');
      return;
    }

    try {
      setLoading(true);
      setOutput('Applying framework-based security control...\n');

      const result = await ipcRenderer.invoke('execute-python-script', 
        'device_config/framework_controls.py', 
        [selectedDevice, selectedControl]
      );

      if (result.success) {
        setOutput(prev => prev + result.output);
      } else {
        setOutput(prev => prev + `Error: ${result.error}\n`);
      }
    } catch (error) {
      setOutput(prev => prev + `Error: ${error.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const getFrameworkColor = (framework) => {
    switch (framework) {
      case 'NIST SP 800-53': return 'bg-blue-100 text-blue-800';
      case 'CIS Controls': return 'bg-green-100 text-green-800';
      case 'Industry Best Practice': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getCategoryColor = (category) => {
    switch (category) {
      case 'Access Control': return 'bg-red-50 text-red-700';
      case 'Network Security': return 'bg-blue-50 text-blue-700';
      case 'Contingency Planning': return 'bg-green-50 text-green-700';
      default: return 'bg-gray-50 text-gray-700';
    }
  };

  const groupedControls = frameworkControls.reduce((acc, control) => {
    if (!acc[control.framework]) {
      acc[control.framework] = [];
    }
    acc[control.framework].push(control);
    return acc;
  }, {});

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Framework Controls</h1>
          <p className="text-gray-600 mt-2">Apply industry-standard security frameworks and controls</p>
        </div>
      </div>

      {/* Framework Overview */}
      <Card title="Security Framework Overview" className="border-l-4 border-l-blue-500">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <BookOpen className="w-8 h-8 text-blue-600 mx-auto mb-2" />
            <h3 className="font-semibold text-blue-900">NIST SP 800-53</h3>
            <p className="text-blue-700">
              {frameworkControls.filter(c => c.framework === 'NIST SP 800-53').length} Controls
            </p>
          </div>
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <BookOpen className="w-8 h-8 text-green-600 mx-auto mb-2" />
            <h3 className="font-semibold text-green-900">CIS Controls</h3>
            <p className="text-green-700">
              {frameworkControls.filter(c => c.framework === 'CIS Controls').length} Controls
            </p>
          </div>
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <BookOpen className="w-8 h-8 text-purple-600 mx-auto mb-2" />
            <h3 className="font-semibold text-purple-900">Best Practices</h3>
            <p className="text-purple-700">
              {frameworkControls.filter(c => c.framework === 'Industry Best Practice').length} Controls
            </p>
          </div>
        </div>
      </Card>

      {/* Device Selection */}
      <Card title="Target Device">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Select Device for Framework Control Application
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
      </Card>

      {/* Framework Controls */}
      <div className="space-y-6">
        {Object.entries(groupedControls).map(([framework, controls]) => (
          <Card key={framework} title={framework}>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {controls.map((control) => (
                <div
                  key={control.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                    selectedControl === control.id
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                  onClick={() => setSelectedControl(control.id)}
                >
                  <div className="flex items-start space-x-3">
                    <input
                      type="radio"
                      name="frameworkControl"
                      checked={selectedControl === control.id}
                      onChange={() => setSelectedControl(control.id)}
                      className="mt-1"
                    />
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{control.name}</h4>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getFrameworkColor(control.framework)}`}>
                          {control.id}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-3">{control.description}</p>
                      <div className="flex items-center justify-between">
                        <span className={`px-2 py-1 text-xs font-medium rounded ${getCategoryColor(control.category)}`}>
                          {control.category}
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {control.controls.map((ctrl, index) => (
                            <span key={index} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                              {ctrl}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        ))}
      </div>

      {/* Action Buttons */}
      <Card>
        <div className="flex space-x-4">
          <Button
            onClick={executeFrameworkControl}
            loading={loading}
            disabled={!selectedDevice || !selectedControl}
            className="flex items-center space-x-2"
          >
            <AlertTriangle className="w-4 h-4" />
            <span>Apply Framework Control</span>
          </Button>

          <Button
            onClick={() => {
              setSelectedControl('');
              setOutput('');
            }}
            variant="outline"
          >
            Clear Selection
          </Button>
        </div>
      </Card>

      {/* Output Terminal */}
      <Card title="Framework Control Output">
        <Terminal output={output} isLoading={loading} />
      </Card>
    </div>
  );
};

export default FrameworkControls;