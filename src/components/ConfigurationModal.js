import React, { useState } from 'react';
import { X } from 'lucide-react';
import Button from './Button';

const ConfigurationModal = ({ isOpen, onClose, onSubmit, control, loading }) => {
  const [formData, setFormData] = useState({});

  if (!isOpen || !control) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const updateFormData = (key, value) => {
    setFormData(prev => ({ ...prev, [key]: value }));
  };

  const renderFormFields = () => {
    switch (control.id) {
      case '3': // Enable Secret
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Enable Secret Password
            </label>
            <input
              type="password"
              value={formData.secret_password || ''}
              onChange={(e) => updateFormData('secret_password', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              placeholder="Enter strong password (min 8 characters)"
              required
              minLength={8}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Password should be at least 8 characters long
            </p>
          </div>
        );

      case '4': // Port Security
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Interface
              </label>
              <input
                type="text"
                value={formData.interface || ''}
                onChange={(e) => updateFormData('interface', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                placeholder="e.g., FastEthernet0/1, GigabitEthernet0/1"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Maximum MAC Addresses
              </label>
              <input
                type="number"
                value={formData.max_mac_addresses || 1}
                onChange={(e) => updateFormData('max_mac_addresses', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="1"
                max="10"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Violation Mode
              </label>
              <select
                value={formData.violation_mode || 'restrict'}
                onChange={(e) => updateFormData('violation_mode', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              >
                <option value="restrict">Restrict - Drop packets and send SNMP trap</option>
                <option value="protect">Protect - Drop packets silently</option>
                <option value="shutdown">Shutdown - Disable the interface</option>
              </select>
            </div>
          </div>
        );

      case '5': // MOTD Banner
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Banner Message
            </label>
            <textarea
              value={formData.banner_message || ''}
              onChange={(e) => updateFormData('banner_message', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              rows="3"
              placeholder="Enter warning message for unauthorized users"
              required
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              This message will be displayed to users upon login
            </p>
          </div>
        );

      case '6': // Exec Timeout
        return (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Minutes
              </label>
              <input
                type="number"
                value={formData.minutes || 10}
                onChange={(e) => updateFormData('minutes', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="0"
                max="35791"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Seconds
              </label>
              <input
                type="number"
                value={formData.seconds || 0}
                onChange={(e) => updateFormData('seconds', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="0"
                max="59"
                required
              />
            </div>
          </div>
        );

      case '7': // Syslog Configuration
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Syslog Server IP Address
            </label>
            <input
              type="text"
              value={formData.syslog_server_ip || ''}
              onChange={(e) => updateFormData('syslog_server_ip', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              placeholder="e.g., 192.168.1.100"
              pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
              required
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Enter the IP address of your syslog server
            </p>
          </div>
        );

      case '8': // BPDU Guard
      case '9': // Root Guard
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Interface(s)
            </label>
            <input
              type="text"
              value={formData.interfaces || ''}
              onChange={(e) => updateFormData('interfaces', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              placeholder="e.g., FastEthernet0/1 or FastEthernet0/1,FastEthernet0/2"
              required
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Enter single interface or comma-separated list for multiple interfaces
            </p>
          </div>
        );

      case '10': // Shutdown Ports
      case '11': // Activate Ports
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Interface
            </label>
            <input
              type="text"
              value={formData.interface || ''}
              onChange={(e) => updateFormData('interface', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              placeholder="e.g., FastEthernet0/1, GigabitEthernet0/1"
              required
            />
          </div>
        );

      case '12': // Disable DTP
      case '13': // Disable CDP
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Interface (Optional)
            </label>
            <input
              type="text"
              value={formData.interface || ''}
              onChange={(e) => updateFormData('interface', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              placeholder="e.g., FastEthernet0/1 (leave blank for global)"
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Leave blank to apply globally, or specify interface for per-interface configuration
            </p>
          </div>
        );

      case '14': // DHCP Snooping
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                VLAN (Optional)
              </label>
              <input
                type="number"
                value={formData.vlan || ''}
                onChange={(e) => updateFormData('vlan', e.target.value ? parseInt(e.target.value) : '')}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                placeholder="e.g., 1 (leave blank for global)"
                min="1"
                max="4094"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Trusted Interface (Optional)
              </label>
              <input
                type="text"
                value={formData.trusted_interface || ''}
                onChange={(e) => updateFormData('trusted_interface', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                placeholder="e.g., FastEthernet0/24 (uplink port)"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Rate Limit Interface (Optional)
              </label>
              <input
                type="text"
                value={formData.rate_limit_interface || ''}
                onChange={(e) => updateFormData('rate_limit_interface', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                placeholder="e.g., FastEthernet0/1"
              />
            </div>
            {formData.rate_limit_interface && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Rate Limit (requests/second)
                </label>
                <input
                  type="number"
                  value={formData.rate_limit || 10}
                  onChange={(e) => updateFormData('rate_limit', parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                  min="1"
                  max="100"
                />
              </div>
            )}
          </div>
        );

      case '15': // Dynamic ARP Inspection
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              VLAN Number
            </label>
            <input
              type="number"
              value={formData.vlan || 1}
              onChange={(e) => updateFormData('vlan', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
              min="1"
              max="4094"
              required
            />
          </div>
        );

      case '16': // Login Block
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Maximum Failed Attempts
              </label>
              <input
                type="number"
                value={formData.attempts || 3}
                onChange={(e) => updateFormData('attempts', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="1"
                max="10"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Block Duration (seconds)
              </label>
              <input
                type="number"
                value={formData.block_for || 60}
                onChange={(e) => updateFormData('block_for', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="1"
                max="3600"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Time Frame (seconds)
              </label>
              <input
                type="number"
                value={formData.within || 120}
                onChange={(e) => updateFormData('within', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-dark-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-dark-orange bg-white dark:bg-dark-secondary text-gray-900 dark:text-white"
                min="1"
                max="3600"
                required
              />
            </div>
          </div>
        );

      default:
        return (
          <div className="text-center py-4">
            <p className="text-gray-600 dark:text-gray-400">
              No additional configuration required for this control.
            </p>
          </div>
        );
    }
  };

  const requiresConfiguration = () => {
    const configRequiredControls = ['3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16'];
    return configRequiredControls.includes(control.id);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-xl max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-dark-accent">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Configure {control.name}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          <div className="mb-4">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {control.description}
            </p>
          </div>

          {requiresConfiguration() ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              {renderFormFields()}
              
              <div className="flex space-x-3 pt-4">
                <Button
                  type="submit"
                  loading={loading}
                  className="flex-1"
                >
                  Apply Configuration
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={onClose}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                This control will be applied with default settings.
              </p>
              <div className="flex space-x-3">
                <Button
                  onClick={() => onSubmit({})}
                  loading={loading}
                  className="flex-1"
                >
                  Apply Control
                </Button>
                <Button
                  variant="outline"
                  onClick={onClose}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ConfigurationModal;