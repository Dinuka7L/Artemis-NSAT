import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import { Network, Plus, Edit, Trash2, Eye, EyeOff } from 'lucide-react';

const { ipcRenderer } = window.require('electron');

const DeviceManagement = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showPasswords, setShowPasswords] = useState({});
  const [formData, setFormData] = useState({
    ip: '',
    devicename: '',
    device_category: 'router',
    username: '',
    password: '',
    enable_secret: ''
  });

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      const result = await ipcRenderer.invoke('get-devices');
      if (result && !result.error) {
        setDevices(result);
      }
    } catch (error) {
      console.error('Error loading devices:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const result = await ipcRenderer.invoke('save-device', formData);
      if (result.success) {
        setShowAddForm(false);
        setFormData({
          ip: '',
          devicename: '',
          device_category: 'router',
          username: '',
          password: '',
          enable_secret: ''
        });
        await loadDevices();
      } else {
        alert('Error saving device: ' + result.error);
      }
    } catch (error) {
      console.error('Error saving device:', error);
      alert('Error saving device');
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = (deviceId, field) => {
    setShowPasswords(prev => ({
      ...prev,
      [`${deviceId}_${field}`]: !prev[`${deviceId}_${field}`]
    }));
  };

  const getDeviceIcon = (category) => {
    const iconClass = "w-5 h-5";
    switch (category) {
      case 'router': return <Network className={`${iconClass} text-blue-600`} />;
      case 'switch': return <Network className={`${iconClass} text-green-600`} />;
      case 'firewall': return <Network className={`${iconClass} text-red-600`} />;
      case 'server': return <Network className={`${iconClass} text-purple-600`} />;
      default: return <Network className={`${iconClass} text-gray-600`} />;
    }
  };

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Device Management</h1>
          <p className="text-gray-600 mt-2">Manage your network devices and credentials</p>
        </div>
        <Button onClick={() => setShowAddForm(true)} className="flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>Add Device</span>
        </Button>
      </div>

      {/* Add Device Form */}
      {showAddForm && (
        <Card title="Add New Device" className="border-l-4 border-l-blue-500">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Device Category
                </label>
                <select
                  value={formData.device_category}
                  onChange={(e) => setFormData({...formData, device_category: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                >
                  <option value="router">Router</option>
                  <option value="switch">Switch</option>
                  <option value="firewall">Firewall</option>
                  <option value="server">Server</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  IP Address
                </label>
                <input
                  type="text"
                  value={formData.ip}
                  onChange={(e) => setFormData({...formData, ip: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="192.168.1.1"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Device Name
                </label>
                <input
                  type="text"
                  value={formData.devicename}
                  onChange={(e) => setFormData({...formData, devicename: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Main Router"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Username
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({...formData, username: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="admin"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({...formData, password: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="••••••••"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Enable Secret
                </label>
                <input
                  type="password"
                  value={formData.enable_secret}
                  onChange={(e) => setFormData({...formData, enable_secret: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            <div className="flex space-x-4">
              <Button type="submit" loading={loading}>
                Add Device
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowAddForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Devices List */}
      <Card title="Configured Devices" subtitle={`${devices.length} devices configured`}>
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="loading-spinner mr-2" />
            <span>Loading devices...</span>
          </div>
        ) : devices.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Device
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    IP Address
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Category
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Username
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Password
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Enable Secret
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {devices.map((device, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getDeviceIcon(device.device_category)}
                        <div className="ml-3">
                          <div className="text-sm font-medium text-gray-900">
                            {device.devicename}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {device.ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        device.device_category === 'router' ? 'bg-blue-100 text-blue-800' :
                        device.device_category === 'switch' ? 'bg-green-100 text-green-800' :
                        device.device_category === 'firewall' ? 'bg-red-100 text-red-800' :
                        'bg-purple-100 text-purple-800'
                      }`}>
                        {device.device_category}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {device.username}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono">
                          {showPasswords[`${index}_password`] ? device.password : '••••••••'}
                        </span>
                        <button
                          onClick={() => togglePasswordVisibility(index, 'password')}
                          className="text-gray-400 hover:text-gray-600"
                        >
                          {showPasswords[`${index}_password`] ? 
                            <EyeOff className="w-4 h-4" /> : 
                            <Eye className="w-4 h-4" />
                          }
                        </button>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono">
                          {showPasswords[`${index}_secret`] ? device.enable_secret : '••••••••'}
                        </span>
                        <button
                          onClick={() => togglePasswordVisibility(index, 'secret')}
                          className="text-gray-400 hover:text-gray-600"
                        >
                          {showPasswords[`${index}_secret`] ? 
                            <EyeOff className="w-4 h-4" /> : 
                            <Eye className="w-4 h-4" />
                          }
                        </button>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button className="text-blue-600 hover:text-blue-900">
                          <Edit className="w-4 h-4" />
                        </button>
                        <button className="text-red-600 hover:text-red-900">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600 mb-4">No devices configured yet</p>
            <Button onClick={() => setShowAddForm(true)}>
              Add Your First Device
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
};

export default DeviceManagement;