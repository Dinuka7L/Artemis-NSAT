// Python bridge utility for handling script execution
class PythonBridge {
  constructor() {
    this.isElectron = typeof window !== 'undefined' && window.require;
    this.ipcRenderer = this.isElectron ? window.require('electron').ipcRenderer : null;
  }

  async executeScript(scriptPath, args = []) {
    if (this.isElectron && this.ipcRenderer) {
      try {
        const result = await this.ipcRenderer.invoke('execute-python-script', scriptPath, args);
        return this.parseScriptOutput(result);
      } catch (error) {
        return {
          success: false,
          error: `Failed to execute script: ${error.message}`,
          output: '',
          parsedData: null
        };
      }
    } else {
      // Mock response for browser environment
      return this.getMockResponse(scriptPath, args);
    }
  }

  parseScriptOutput(result) {
    if (!result.success) {
      return {
        success: false,
        error: result.error || 'Script execution failed',
        output: result.output || '',
        parsedData: null
      };
    }

    let parsedData = null;
    let cleanOutput = result.output || '';

    try {
      // Try to extract JSON data from output
      const jsonMatch = cleanOutput.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsedData = JSON.parse(jsonMatch[0]);
      }

      // Extract structured data patterns
      const deviceMatch = cleanOutput.match(/Device:\s*(.+)/g);
      const statusMatch = cleanOutput.match(/Status:\s*(.+)/g);
      const resultMatch = cleanOutput.match(/Result:\s*(.+)/g);

      if (deviceMatch || statusMatch || resultMatch) {
        parsedData = {
          devices: deviceMatch ? deviceMatch.map(m => m.replace('Device: ', '').trim()) : [],
          statuses: statusMatch ? statusMatch.map(m => m.replace('Status: ', '').trim()) : [],
          results: resultMatch ? resultMatch.map(m => m.replace('Result: ', '').trim()) : []
        };
      }

      // Clean up output for display
      cleanOutput = cleanOutput
        .replace(/\x1b\[[0-9;]*m/g, '') // Remove ANSI color codes
        .replace(/\r\n/g, '\n') // Normalize line endings
        .trim();

    } catch (error) {
      console.warn('Failed to parse script output:', error);
    }

    return {
      success: true,
      error: null,
      output: cleanOutput,
      parsedData: parsedData
    };
  }

  getMockResponse(scriptPath, args) {
    const mockResponses = {
      'device_config/network_configuration_manager.py': {
        success: true,
        output: `Device Configuration Retrieved Successfully
Device: ${args[0] || 'Router-1'} (${args[0] || '192.168.1.1'})
Status: Connected
Telnet: Disabled
SSH: Enabled (v2)
Password Encryption: Enabled
Enable Secret: Configured
MOTD Banner: Configured
Syslog: Enabled (192.168.1.100)
Exec Timeout: 10 minutes

Configuration retrieval completed.`,
        parsedData: {
          device: args[0] || 'Router-1',
          ip: args[0] || '192.168.1.1',
          telnet: 'Disabled',
          ssh: 'Enabled (v2)',
          passwordEncryption: 'Enabled',
          enableSecret: 'Configured',
          motdBanner: 'Configured',
          syslog: 'Enabled (192.168.1.100)',
          execTimeout: '10 minutes'
        }
      },
      'device_config/device_control.py': {
        success: true,
        output: `Device Configuration Applied Successfully
Device: ${args[0] || 'Router-1'} (${args[0] || '192.168.1.1'})
Status: Connected

Applying Configuration Controls:
${args[1] ? args[1].split(',').map(id => {
  const controlNames = {
    '1': '✓ Telnet disabled successfully',
    '2': '✓ Password encryption enabled',
    '3': '✓ Enable secret configured',
    '4': '✓ Port security configured on specified interface',
    '5': '✓ MOTD banner configured',
    '6': '✓ Exec timeout configured',
    '7': '✓ Syslog server configured',
    '8': '✓ BPDU Guard enabled on specified interfaces',
    '9': '✓ Root Guard enabled on specified interfaces',
    '10': '✓ Interface administratively shut down',
    '11': '✓ Interface activated',
    '12': '✓ DTP disabled on interface',
    '13': '✓ CDP disabled',
    '14': '✓ DHCP Snooping configured',
    '15': '✓ Dynamic ARP Inspection enabled',
    '16': '✓ Login block configured'
  };
  return controlNames[id] || `✓ Control ${id} applied`;
}).join('\n') : '✓ Default configuration applied'}

Configuration deployment completed successfully.
${args[1] ? args[1].split(',').length : 1} security controls applied.

${args[2] ? `Configuration Parameters Applied:
${JSON.stringify(JSON.parse(args[2]), null, 2)}` : ''}`,
        parsedData: {
          device: args[0] || 'Router-1',
          controlsApplied: args[1] ? args[1].split(',').length : 1,
          configurationData: args[2] ? JSON.parse(args[2]) : null,
          results: args[1] ? args[1].split(',').map(id => ({
            control: `Control ${id}`,
            status: 'Success'
          })) : [{ control: 'Default Control', status: 'Success' }]
        }
      },
      'device_config/attack_mitigation.py': {
        success: true,
        output: `Attack Mitigation Deployment Started
Device: ${args[0] || 'Router-1'} (${args[0] || '192.168.1.1'})
Status: Connected

Applying Security Controls:
✓ Telnet disabled successfully
✓ Password encryption enabled
✓ Enable secret configured
✓ MOTD banner configured
✓ Exec timeout set to 10 minutes

Attack mitigation deployment completed successfully.
5 security controls applied.`,
        parsedData: {
          device: args[0] || 'Router-1',
          controlsApplied: 5,
          results: [
            { control: 'Disable Telnet', status: 'Success' },
            { control: 'Password Encryption', status: 'Success' },
            { control: 'Enable Secret', status: 'Success' },
            { control: 'MOTD Banner', status: 'Success' },
            { control: 'Exec Timeout', status: 'Success' }
          ]
        }
      },
      'network_compliance/check_compliance.py': {
        success: true,
        output: `Network Compliance Check Started
Devices Selected: 2
Controls Selected: 8

Overall Security Compliance Score: 87.5%

Device Compliance Details:
Router-1 (192.168.1.1):
  - Telnet Disabled: Pass
  - SSH V2 Enabled: Pass
  - Password Encryption: Pass
  - Enable Secret: Pass
  - MOTD Banner: Pass
  - Syslog: Pass
  - Exec Timeout: Pass
  - Port Security: Fail (3 ports unsecured)

Switch-1 (192.168.1.2):
  - Port Security: Pass
  - BPDU Guard: Pass
  - Root Guard: Fail (2 ports unprotected)
  - DHCP Snooping: Pass

Compliance check completed.
Report generated: compliance_report_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.pdf`,
        parsedData: {
          overallScore: 87.5,
          devicesChecked: 2,
          controlsChecked: 8,
          deviceResults: [
            {
              device: 'Router-1',
              ip: '192.168.1.1',
              passed: 7,
              failed: 1,
              controls: [
                { name: 'Telnet Disabled', status: 'Pass' },
                { name: 'SSH V2 Enabled', status: 'Pass' },
                { name: 'Password Encryption', status: 'Pass' },
                { name: 'Enable Secret', status: 'Pass' },
                { name: 'MOTD Banner', status: 'Pass' },
                { name: 'Syslog', status: 'Pass' },
                { name: 'Exec Timeout', status: 'Pass' },
                { name: 'Port Security', status: 'Fail' }
              ]
            },
            {
              device: 'Switch-1',
              ip: '192.168.1.2',
              passed: 3,
              failed: 1,
              controls: [
                { name: 'Port Security', status: 'Pass' },
                { name: 'BPDU Guard', status: 'Pass' },
                { name: 'Root Guard', status: 'Fail' },
                { name: 'DHCP Snooping', status: 'Pass' }
              ]
            }
          ]
        }
      },
      'device_config/framework_controls.py': {
        success: true,
        output: `Framework Control Application Started
Device: ${args[0] || 'Router-1'} (${args[0] || '192.168.1.1'})
Framework: NIST SP 800-53
Control: ${args[1] || 'AC-6-3'} (Network Access to Privileged Commands)

Applying control requirements:
✓ Enable secret configured
✓ Telnet access disabled
✓ SSH v2 enabled and configured
✓ Privileged access restrictions applied

Framework control ${args[1] || 'AC-6-3'} applied successfully.
Device compliance improved.`,
        parsedData: {
          device: args[0] || 'Router-1',
          framework: 'NIST SP 800-53',
          control: args[1] || 'AC-6-3',
          controlName: 'Network Access to Privileged Commands',
          requirements: [
            { requirement: 'Enable secret configured', status: 'Success' },
            { requirement: 'Telnet access disabled', status: 'Success' },
            { requirement: 'SSH v2 enabled', status: 'Success' },
            { requirement: 'Privileged access restrictions', status: 'Success' }
          ]
        }
      }
    };

    return mockResponses[scriptPath] || {
      success: true,
      output: `Mock execution of ${scriptPath} with args: ${args.join(', ')}\nScript would execute in Electron environment.`,
      parsedData: null
    };
  }

  async getDevices() {
    if (this.isElectron && this.ipcRenderer) {
      try {
        const result = await this.ipcRenderer.invoke('get-devices');
        return result.error ? [] : result;
      } catch (error) {
        console.error('Error loading devices:', error);
        return [];
      }
    } else {
      // Mock devices for browser environment
      return [
        { 
          devicename: 'Border-Router', 
          ip: '192.168.80.1', 
          device_category: 'router',
          username: 'admin',
          password: 'cisco',
          enable_secret: 'class'
        },
        { 
          devicename: 'DHCP-R', 
          ip: '192.168.86.4', 
          device_category: 'router',
          username: 'admin', 
          password: 'cisco',
          enable_secret: 'class'
        },
        { 
          devicename: 'Core-Switch', 
          ip: '192.168.1.10', 
          device_category: 'switch',
          username: 'admin',
          password: 'switch123',
          enable_secret: 'enable123'
        }
      ];
    }
  }

  async saveDevice(deviceData) {
    if (this.isElectron && this.ipcRenderer) {
      try {
        const result = await this.ipcRenderer.invoke('save-device', deviceData);
        return result;
      } catch (error) {
        return { success: false, error: error.message };
      }
    } else {
      // Mock save for browser environment
      console.log('Mock: Device would be saved in Electron environment', deviceData);
      return { success: true, message: 'Device saved successfully (mock)' };
    }
  }

  formatOutput(output, parsedData = null) {
    if (!output) return '';

    let formatted = output;

    // Add timestamps to output lines
    const lines = formatted.split('\n');
    const timestampedLines = lines.map(line => {
      if (line.trim() && !line.match(/^\[\d{2}:\d{2}:\d{2}\]/)) {
        const timestamp = new Date().toLocaleTimeString();
        return `[${timestamp}] ${line}`;
      }
      return line;
    });

    formatted = timestampedLines.join('\n');

    // Add summary if parsed data is available
    if (parsedData) {
      formatted += '\n\n--- Summary ---\n';
      if (parsedData.device) {
        formatted += `Device: ${parsedData.device}\n`;
      }
      if (parsedData.controlsApplied) {
        formatted += `Controls Applied: ${parsedData.controlsApplied}\n`;
      }
      if (parsedData.overallScore) {
        formatted += `Compliance Score: ${parsedData.overallScore}%\n`;
      }
      if (parsedData.configurationData) {
        formatted += `Configuration Parameters: ${JSON.stringify(parsedData.configurationData, null, 2)}\n`;
      }
    }

    return formatted;
  }
}

export default new PythonBridge();