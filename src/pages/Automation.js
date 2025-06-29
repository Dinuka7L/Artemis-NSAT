import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import { 
  Clock, 
  Play, 
  Pause, 
  Settings, 
  Mail, 
  AlertTriangle, 
  Calendar,
  Plus,
  Edit,
  Trash2,
  CheckCircle,
  XCircle
} from 'lucide-react';

const ipcRenderer = window.require ? window.require('electron').ipcRenderer : null;

const Automation = () => {
  const [schedules, setSchedules] = useState([]);
  const [emailLists, setEmailLists] = useState([]);
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [showEmailForm, setShowEmailForm] = useState(false);
  const [loading, setLoading] = useState(false);
  
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    description: '',
    frequency: 'daily',
    time: '09:00',
    devices: [],
    scanType: 'compliance',
    emailList: '',
    severity: 'medium',
    enabled: true
  });

  const [emailForm, setEmailForm] = useState({
    name: '',
    description: '',
    emails: ['']
  });

  useEffect(() => {
    loadSchedules();
    loadEmailLists();
  }, []);

  const loadSchedules = () => {
    // Mock data for schedules
    const mockSchedules = [
      {
        id: 1,
        name: 'Daily Security Scan',
        description: 'Comprehensive security assessment of all network devices',
        frequency: 'daily',
        time: '09:00',
        devices: ['Router-1', 'Switch-1'],
        scanType: 'compliance',
        emailList: 'Security Team',
        severity: 'high',
        enabled: true,
        lastRun: '2025-01-23 09:00:00',
        nextRun: '2025-01-24 09:00:00',
        status: 'active'
      },
      {
        id: 2,
        name: 'Weekly Posture Report',
        description: 'Weekly network security posture assessment',
        frequency: 'weekly',
        time: '08:00',
        devices: ['Router-1'],
        scanType: 'posture',
        emailList: 'Management',
        severity: 'medium',
        enabled: false,
        lastRun: '2025-01-20 08:00:00',
        nextRun: '2025-01-27 08:00:00',
        status: 'paused'
      }
    ];
    setSchedules(mockSchedules);
  };

  const loadEmailLists = () => {
    // Mock data for email lists
    const mockEmailLists = [
      {
        id: 1,
        name: 'Security Team',
        description: 'Network security administrators',
        emails: ['security@company.com', 'admin@company.com']
      },
      {
        id: 2,
        name: 'Management',
        description: 'Executive management team',
        emails: ['cto@company.com', 'manager@company.com']
      }
    ];
    setEmailLists(mockEmailLists);
  };

  const handleScheduleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      
      if (ipcRenderer) {
        // In a real implementation, this would save the schedule
        const result = await ipcRenderer.invoke('save-automation-schedule', scheduleForm);
        if (result.success) {
          setShowScheduleForm(false);
          setScheduleForm({
            name: '',
            description: '',
            frequency: 'daily',
            time: '09:00',
            devices: [],
            scanType: 'compliance',
            emailList: '',
            severity: 'medium',
            enabled: true
          });
          loadSchedules();
        }
      } else {
        // Mock save for browser environment
        alert('Schedule would be saved in Electron environment');
        setShowScheduleForm(false);
      }
    } catch (error) {
      console.error('Error saving schedule:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEmailListSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      
      if (ipcRenderer) {
        // In a real implementation, this would save the email list
        const result = await ipcRenderer.invoke('save-email-list', emailForm);
        if (result.success) {
          setShowEmailForm(false);
          setEmailForm({
            name: '',
            description: '',
            emails: ['']
          });
          loadEmailLists();
        }
      } else {
        // Mock save for browser environment
        alert('Email list would be saved in Electron environment');
        setShowEmailForm(false);
      }
    } catch (error) {
      console.error('Error saving email list:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleSchedule = async (scheduleId) => {
    try {
      if (ipcRenderer) {
        await ipcRenderer.invoke('toggle-schedule', scheduleId);
        loadSchedules();
      } else {
        // Mock toggle for browser environment
        setSchedules(prev => prev.map(schedule => 
          schedule.id === scheduleId 
            ? { ...schedule, enabled: !schedule.enabled, status: schedule.enabled ? 'paused' : 'active' }
            : schedule
        ));
      }
    } catch (error) {
      console.error('Error toggling schedule:', error);
    }
  };

  const runScheduleNow = async (scheduleId) => {
    try {
      setLoading(true);
      if (ipcRenderer) {
        const result = await ipcRenderer.invoke('run-schedule-now', scheduleId);
        if (result.success) {
          alert('Scan started successfully!');
        }
      } else {
        // Mock run for browser environment
        alert('Scan would be executed in Electron environment');
      }
    } catch (error) {
      console.error('Error running schedule:', error);
    } finally {
      setLoading(false);
    }
  };

  const addEmailField = () => {
    setEmailForm(prev => ({
      ...prev,
      emails: [...prev.emails, '']
    }));
  };

  const updateEmailField = (index, value) => {
    setEmailForm(prev => ({
      ...prev,
      emails: prev.emails.map((email, i) => i === index ? value : email)
    }));
  };

  const removeEmailField = (index) => {
    setEmailForm(prev => ({
      ...prev,
      emails: prev.emails.filter((_, i) => i !== index)
    }));
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active': return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'paused': return <Pause className="w-5 h-5 text-yellow-600" />;
      case 'error': return <XCircle className="w-5 h-5 text-red-600" />;
      default: return <Clock className="w-5 h-5 text-gray-600" />;
    }
  };

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Automation</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Schedule automatic network scans and configure email notifications
          </p>
        </div>
        <div className="flex space-x-4">
          <Button 
            onClick={() => setShowEmailForm(true)} 
            variant="secondary"
            className="flex items-center space-x-2"
          >
            <Mail className="w-4 h-4" />
            <span>Manage Email Lists</span>
          </Button>
          <Button 
            onClick={() => setShowScheduleForm(true)} 
            className="flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>New Schedule</span>
          </Button>
        </div>
      </div>

      {/* Automation Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg mx-auto mb-4">
            <Clock className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white">{schedules.length}</h3>
          <p className="text-gray-600 dark:text-gray-400">Total Schedules</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg mx-auto mb-4">
            <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white">
            {schedules.filter(s => s.enabled).length}
          </h3>
          <p className="text-gray-600 dark:text-gray-400">Active Schedules</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg mx-auto mb-4">
            <Mail className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white">{emailLists.length}</h3>
          <p className="text-gray-600 dark:text-gray-400">Email Lists</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-yellow-100 dark:bg-yellow-900 rounded-lg mx-auto mb-4">
            <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white">
            {schedules.filter(s => s.severity === 'high').length}
          </h3>
          <p className="text-gray-600 dark:text-gray-400">High Priority</p>
        </Card>
      </div>

      {/* Schedule Form */}
      {showScheduleForm && (
        <Card title="Create New Schedule" className="border-l-4 border-l-blue-500 dark:border-l-dark-orange">
          <form onSubmit={handleScheduleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Schedule Name
                </label>
                <input
                  type="text"
                  value={scheduleForm.name}
                  onChange={(e) => setScheduleForm({...scheduleForm, name: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                  placeholder="Daily Security Scan"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Frequency
                </label>
                <select
                  value={scheduleForm.frequency}
                  onChange={(e) => setScheduleForm({...scheduleForm, frequency: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                >
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Time
                </label>
                <input
                  type="time"
                  value={scheduleForm.time}
                  onChange={(e) => setScheduleForm({...scheduleForm, time: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Scan Type
                </label>
                <select
                  value={scheduleForm.scanType}
                  onChange={(e) => setScheduleForm({...scheduleForm, scanType: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                >
                  <option value="compliance">Compliance Check</option>
                  <option value="posture">Security Posture</option>
                  <option value="vulnerability">Vulnerability Scan</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Email List
                </label>
                <select
                  value={scheduleForm.emailList}
                  onChange={(e) => setScheduleForm({...scheduleForm, emailList: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                >
                  <option value="">Select email list...</option>
                  {emailLists.map((list) => (
                    <option key={list.id} value={list.name}>{list.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Severity Threshold
                </label>
                <select
                  value={scheduleForm.severity}
                  onChange={(e) => setScheduleForm({...scheduleForm, severity: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                >
                  <option value="low">Low - Send all reports</option>
                  <option value="medium">Medium - Send medium+ issues</option>
                  <option value="high">High - Send only critical issues</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Description
              </label>
              <textarea
                value={scheduleForm.description}
                onChange={(e) => setScheduleForm({...scheduleForm, description: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                rows="3"
                placeholder="Describe what this schedule does..."
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                id="enabled"
                checked={scheduleForm.enabled}
                onChange={(e) => setScheduleForm({...scheduleForm, enabled: e.target.checked})}
                className="rounded border-gray-300 dark:border-dark-accent"
              />
              <label htmlFor="enabled" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                Enable this schedule immediately
              </label>
            </div>

            <div className="flex space-x-4">
              <Button type="submit" loading={loading}>
                Create Schedule
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowScheduleForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Email List Form */}
      {showEmailForm && (
        <Card title="Manage Email Lists" className="border-l-4 border-l-purple-500 dark:border-l-dark-orange">
          <form onSubmit={handleEmailListSubmit} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  List Name
                </label>
                <input
                  type="text"
                  value={emailForm.name}
                  onChange={(e) => setEmailForm({...emailForm, name: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                  placeholder="Security Team"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Description
                </label>
                <input
                  type="text"
                  value={emailForm.description}
                  onChange={(e) => setEmailForm({...emailForm, description: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                  placeholder="Network security administrators"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Email Addresses
              </label>
              {emailForm.emails.map((email, index) => (
                <div key={index} className="flex space-x-2 mb-2">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => updateEmailField(index, e.target.value)}
                    className="flex-1 px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                    placeholder="email@company.com"
                    required
                  />
                  {emailForm.emails.length > 1 && (
                    <Button
                      type="button"
                      variant="danger"
                      size="sm"
                      onClick={() => removeEmailField(index)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addEmailField}
                className="mt-2"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Email
              </Button>
            </div>

            <div className="flex space-x-4">
              <Button type="submit" loading={loading}>
                Save Email List
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowEmailForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Scheduled Scans */}
      <Card title="Scheduled Scans" subtitle={`${schedules.length} schedules configured`}>
        {schedules.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-dark-accent">
              <thead className="bg-gray-50 dark:bg-dark-accent">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Schedule
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Frequency
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Next Run
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-dark-secondary divide-y divide-gray-200 dark:divide-dark-accent">
                {schedules.map((schedule) => (
                  <tr key={schedule.id} className="hover:bg-gray-50 dark:hover:bg-dark-accent">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <Clock className="w-5 h-5 text-gray-400 dark:text-gray-500 mr-3" />
                        <div>
                          <div className="text-sm font-medium text-gray-900 dark:text-white">
                            {schedule.name}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {schedule.description}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {schedule.frequency} at {schedule.time}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 text-gray-400 dark:text-gray-500 mr-2" />
                        {new Date(schedule.nextRun).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(schedule.severity)}`}>
                        {schedule.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(schedule.status)}
                        <span className="ml-2 text-sm text-gray-900 dark:text-white capitalize">
                          {schedule.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => toggleSchedule(schedule.id)}
                          className="text-blue-600 dark:text-dark-orange hover:text-blue-900 dark:hover:text-dark-orange-light"
                          title={schedule.enabled ? 'Pause' : 'Resume'}
                        >
                          {schedule.enabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                        </button>
                        <button
                          onClick={() => runScheduleNow(schedule.id)}
                          className="text-green-600 hover:text-green-900"
                          title="Run Now"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
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
            <Clock className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
            <p className="text-gray-600 dark:text-gray-400 mb-4">No schedules configured yet</p>
            <Button onClick={() => setShowScheduleForm(true)}>
              Create Your First Schedule
            </Button>
          </div>
        )}
      </Card>

      {/* Email Lists */}
      <Card title="Email Lists" subtitle={`${emailLists.length} lists configured`}>
        {emailLists.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {emailLists.map((list) => (
              <div key={list.id} className="border border-gray-200 dark:border-dark-accent rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-gray-900 dark:text-white">{list.name}</h4>
                  <div className="flex space-x-2">
                    <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
                      <Edit className="w-4 h-4" />
                    </button>
                    <button className="text-red-600 hover:text-red-900">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{list.description}</p>
                <div className="space-y-1">
                  {list.emails.map((email, index) => (
                    <div key={index} className="flex items-center text-sm text-gray-700 dark:text-gray-300">
                      <Mail className="w-3 h-3 mr-2 text-gray-400 dark:text-gray-500" />
                      {email}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <Mail className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
            <p className="text-gray-600 dark:text-gray-400 mb-4">No email lists configured yet</p>
            <Button onClick={() => setShowEmailForm(true)}>
              Create Your First Email List
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
};

export default Automation;