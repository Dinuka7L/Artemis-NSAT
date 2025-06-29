import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Button from '../components/Button';
import { 
  Shield, 
  Network, 
  Settings, 
  AlertTriangle, 
  BarChart3, 
  FileText,
  Activity,
  Server,
  Lock
} from 'lucide-react';

const { ipcRenderer } = window.require('electron');

const Dashboard = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalDevices: 0,
    routers: 0,
    switches: 0,
    firewalls: 0,
    servers: 0
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
        calculateStats(result);
      }
    } catch (error) {
      console.error('Error loading devices:', error);
    } finally {
      setLoading(false);
    }
  };

  const calculateStats = (deviceList) => {
    const stats = {
      totalDevices: deviceList.length,
      routers: deviceList.filter(d => d.device_category === 'router').length,
      switches: deviceList.filter(d => d.device_category === 'switch').length,
      firewalls: deviceList.filter(d => d.device_category === 'firewall').length,
      servers: deviceList.filter(d => d.device_category === 'server').length
    };
    setStats(stats);
  };

  const quickActions = [
    {
      title: 'Device Management',
      description: 'Add, configure, and manage network devices',
      icon: Network,
      color: 'bg-blue-500',
      path: '/device-management'
    },
    {
      title: 'Attack Mitigation',
      description: 'Deploy security controls against common attacks',
      icon: Shield,
      color: 'bg-red-500',
      path: '/attack-mitigation'
    },
    {
      title: 'Network Compliance',
      description: 'Check compliance and generate reports',
      icon: BarChart3,
      color: 'bg-green-500',
      path: '/network-compliance'
    },
    {
      title: 'Framework Controls',
      description: 'Apply industry-standard security frameworks',
      icon: AlertTriangle,
      color: 'bg-yellow-500',
      path: '/framework-controls'
    }
  ];

  return (
    <div className="space-y-6 fade-in">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-red-600 to-red-800 rounded-lg p-8 text-white">
        <div className="flex items-center space-x-4">
          <Shield className="w-12 h-12" />
          <div>
            <h1 className="text-3xl font-bold">Welcome to ARTEMIS</h1>
            <p className="text-red-100 mt-2">
              Network Security Automation Toolkit - Streamline your network security operations
            </p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-blue-100 rounded-lg mx-auto mb-4">
            <Network className="w-6 h-6 text-blue-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{stats.totalDevices}</h3>
          <p className="text-gray-600">Total Devices</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-green-100 rounded-lg mx-auto mb-4">
            <Activity className="w-6 h-6 text-green-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{stats.routers}</h3>
          <p className="text-gray-600">Routers</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-purple-100 rounded-lg mx-auto mb-4">
            <Settings className="w-6 h-6 text-purple-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{stats.switches}</h3>
          <p className="text-gray-600">Switches</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-red-100 rounded-lg mx-auto mb-4">
            <Lock className="w-6 h-6 text-red-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{stats.firewalls}</h3>
          <p className="text-gray-600">Firewalls</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-yellow-100 rounded-lg mx-auto mb-4">
            <Server className="w-6 h-6 text-yellow-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{stats.servers}</h3>
          <p className="text-gray-600">Servers</p>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {quickActions.map((action, index) => {
          const Icon = action.icon;
          return (
            <Card key={index} className="hover:shadow-lg transition-shadow duration-200 cursor-pointer">
              <div className="text-center">
                <div className={`flex items-center justify-center w-16 h-16 ${action.color} rounded-lg mx-auto mb-4`}>
                  <Icon className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">{action.title}</h3>
                <p className="text-gray-600 mb-4">{action.description}</p>
                <Button
                  onClick={() => navigate(action.path)}
                  variant="outline"
                  size="sm"
                  className="w-full"
                >
                  Get Started
                </Button>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Recent Devices */}
      <Card title="Recent Devices" subtitle="Recently added or modified devices">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="loading-spinner mr-2" />
            <span>Loading devices...</span>
          </div>
        ) : devices.length > 0 ? (
          <div className="space-y-4">
            {devices.slice(0, 5).map((device, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Network className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-900">{device.devicename}</h4>
                    <p className="text-sm text-gray-600">{device.ip} • {device.device_category}</p>
                  </div>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm">
                  Active
                </span>
              </div>
            ))}
            {devices.length > 5 && (
              <Button
                onClick={() => navigate('/device-management')}
                variant="outline"
                size="sm"
                className="w-full mt-4"
              >
                View All Devices ({devices.length})
              </Button>
            )}
          </div>
        ) : (
          <div className="text-center py-8">
            <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600 mb-4">No devices configured yet</p>
            <Button onClick={() => navigate('/device-management')}>
              Add Your First Device
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
};

export default Dashboard;