import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import Terminal from '../components/Terminal';
import { BarChart3, Play, Download, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

const { ipcRenderer } = window.require('electron');

const NetworkCompliance = () => {
  const [devices, setDevices] = useState([]);
  const [selectedDevices, setSelectedDevices] = useState([]);
  const [selectedControls, setSelectedControls] = useState([]);
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [complianceResults, setComplianceResults] = useState(null);

  const complianceControls = [
    { id: '1', name: 'Telnet Disabled', weight: 5, category: 'Access Control' },
    { id: '2', name: 'SSH V2 Enabled', weight: 5, category: 'Access Control' },
    { id: '3', name: 'Password Encryption', weight: 10, category: 'Cryptography' },
    { id: '4', name: 'Privilege Exec Password', weight: 10, category: 'Access Control' },
    { id: '5', name: 'Enable MOTD', weight: 3, category: 'Awareness' },
    { id: '6', name: 'Syslog', weight: 5, category: 'Audit & Accountability' },
    { id: '7', name: 'Exec Timeout', weight: 5, category: 'Session Management' },
    { id: '8', name: 'Port Security on Interfaces', weight: 15, category: 'Network Security' },
    { id: '9', name: 'BPDU Guard', weight: 5, category: 'Network Security' },
    { id: '10', name: 'Root Guard', weight: 5, category: 'Network Security' },
    { id: '11', name: 'Disable DTP', weight: 5, category: 'Network Security' },
    { id: '12', name: 'Disable CDP', weight: 5, category: 'Network Security' },
    { id: '13', name: 'DHCP Snooping', weight: 10, category: 'Network Security' },
    { id: '14', name: 'Dynamic ARP Inspection', weight: 10, category: 'Network Security' },
    { id: '15', name: 'Login Fail Lock', weight: 7, category: 'Access Control' }
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

  const handleDeviceToggle = (deviceIp) => {
    setSelectedDevices(prev => 
      prev.includes(deviceIp) 
        ? prev.filter(ip => ip !== deviceIp)
        : [...prev, deviceIp]
    );
  };

  const handleControlToggle = (controlId) => {
    setSelectedControls(prev => 
      prev.includes(controlId) 
        ? prev.filter(id => id !== controlId)
        : [...prev, controlId]
    );
  };

  const runComplianceCheck = async () => {
    if (selectedDevices.length === 0 || selectedControls.length === 0) {
      alert('Please select at least one device and one control');
      return;
    }

    try {
      setLoading(true);
      setOutput('Starting compliance check...\n');

      const result = await ipcRenderer.invoke('execute-python-script', 
        'network_compliance/check_compliance.py', 
        [selectedDevices.join(','), selectedControls.join(',')]
      );

      if (result.success) {
        setOutput(prev => prev + result.output);
        // Parse compliance results if available
        try {
          const resultsMatch = result.output.match(/COMPLIANCE_RESULTS:(.*?)END_RESULTS/s);
          if (resultsMatch) {
            const complianceData = JSON.parse(resultsMatch[1]);
            setComplianceResults(complianceData);
          }
        } catch (e) {
          console.log('Could not parse compliance results');
        }
      } else {
        setOutput(prev => prev + `Error: ${result.error}\n`);
      }
    } catch (error) {
      setOutput(prev => prev + `Error: ${error.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const generateComplianceReport = async () => {
    if (selectedDevices.length === 0) {
      alert('Please select at least one device');
      return;
    }

    try {
      setLoading(true);
      const result = await ipcRenderer.invoke('execute-python-script', 
        'network_compliance/check_compliance.py', 
        [selectedDevices.join(','), 'generate_report']
      );

      if (result.success) {
        setOutput(prev => prev + 'Compliance report generated successfully!\n' + result.output);
      } else {
        setOutput(prev => prev + `Error generating report: ${result.error}\n`);
      }
    } catch (error) {
      setOutput(prev => prev + `Error: ${error.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const getCategoryColor = (category) => {
    const colors = {
      'Access Control': 'bg-red-50 text-red-700',
      'Cryptography': 'bg-purple-50 text-purple-700',
      'Awareness': 'bg-blue-50 text-blue-700',
      'Audit & Accountability': 'bg-green-50 text-green-700',
      'Session Management': 'bg-yellow-50 text-yellow-700',
      'Network Security': 'bg-indigo-50 text-indigo-700'
    };
    return colors[category] || 'bg-gray-50 text-gray-700';
  };

  const getComplianceIcon = (status) => {
    switch (status) {
      case 'Pass': return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'Fail': return <XCircle className="w-5 h-5 text-red-600" />;
      default: return <AlertCircle className="w-5 h-5 text-yellow-600" />;
    }
  };

  const totalWeight = selectedControls.reduce((sum, controlId) => {
    const control = complianceControls.find(c => c.id === controlId);
    return sum + (control ? control.weight : 0);
  }, 0);

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Network Compliance</h1>
          <p className="text-gray-600 mt-2">Assess network security compliance and generate reports</p>
        </div>
      </div>

      {/* Compliance Overview */}
      <Card title="Compliance Assessment Overview" className="border-l-4 border-l-green-500">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <BarChart3 className="w-8 h-8 text-blue-600 mx-auto mb-2" />
            <h3 className="font-semibold text-blue-900">Total Controls</h3>
            <p className="text-blue-700">{complianceControls.length}</p>
          </div>
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
            <h3 className="font-semibold text-green-900">Selected Controls</h3>
            <p className="text-green-700">{selectedControls.length}</p>
          </div>
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <AlertCircle className="w-8 h-8 text-purple-600 mx-auto mb-2" />
            <h3 className="font-semibold text-purple-900">Total Weight</h3>
            <p className="text-purple-700">{totalWeight}</p>
          </div>
          <div className="text-center p-4 bg-yellow-50 rounded-lg">
            <BarChart3 className="w-8 h-8 text-yellow-600 mx-auto mb-2" />
            <h3 className="font-semibold text-yellow-900">Selected Devices</h3>
            <p className="text-yellow-700">{selectedDevices.length}</p>
          </div>
        </div>
      </Card>

      {/* Device Selection */}
      <Card title="Device Selection">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {devices.map((device, index) => (
            <div
              key={index}
              className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                selectedDevices.includes(device.ip)
                  ? 'border-green-500 bg-green-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
              onClick={() => handleDeviceToggle(device.ip)}
            >
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={selectedDevices.includes(device.ip)}
                  onChange={() => handleDeviceToggle(device.ip)}
                  className="rounded"
                />
                <div>
                  <h4 className="font-medium text-gray-900">{device.devicename}</h4>
                  <p className="text-sm text-gray-600">{device.ip} • {device.device_category}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Compliance Controls */}
      <Card title="Compliance Controls">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {complianceControls.map((control) => (
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
                  className="mt-1 rounded"
                />
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-gray-900">{control.name}</h4>
                    <span className="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-700 rounded">
                      Weight: {control.weight}
                    </span>
                  </div>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getCategoryColor(control.category)}`}>
                    {control.category}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex space-x-4 mt-6">
          <Button
            onClick={runComplianceCheck}
            loading={loading}
            disabled={selectedDevices.length === 0 || selectedControls.length === 0}
            className="flex items-center space-x-2"
          >
            <Play className="w-4 h-4" />
            <span>Run Compliance Check</span>
          </Button>

          <Button
            onClick={generateComplianceReport}
            variant="secondary"
            disabled={selectedDevices.length === 0}
            className="flex items-center space-x-2"
          >
            <Download className="w-4 h-4" />
            <span>Generate Report</span>
          </Button>

          <Button
            onClick={() => {
              setSelectedControls([]);
              setSelectedDevices([]);
              setOutput('');
              setComplianceResults(null);
            }}
            variant="outline"
          >
            Clear All
          </Button>

          <Button
            onClick={() => {
              const allControlIds = complianceControls.map(c => c.id);
              setSelectedControls(allControlIds);
            }}
            variant="success"
          >
            Select All Controls
          </Button>
        </div>
      </Card>

      {/* Compliance Results */}
      {complianceResults && (
        <Card title="Compliance Results" className="border-l-4 border-l-blue-500">
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <h3 className="font-semibold text-green-900">Overall Score</h3>
                <p className="text-2xl font-bold text-green-700">
                  {complianceResults.overallScore || 'N/A'}%
                </p>
              </div>
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <h3 className="font-semibold text-blue-900">Passed Controls</h3>
                <p className="text-2xl font-bold text-blue-700">
                  {complianceResults.passedControls || 0}
                </p>
              </div>
              <div className="text-center p-4 bg-red-50 rounded-lg">
                <h3 className="font-semibold text-red-900">Failed Controls</h3>
                <p className="text-2xl font-bold text-red-700">
                  {complianceResults.failedControls || 0}
                </p>
              </div>
            </div>

            {complianceResults.deviceResults && (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Device
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Control
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Score
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {complianceResults.deviceResults.map((result, index) => (
                      <tr key={index} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {result.device}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.control}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {getComplianceIcon(result.status)}
                            <span className="ml-2 text-sm text-gray-900">{result.status}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {result.score}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Output Terminal */}
      <Card title="Compliance Check Output">
        <Terminal output={output} isLoading={loading} />
      </Card>
    </div>
  );
};

export default NetworkCompliance;