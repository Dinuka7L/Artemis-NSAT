// Python bridge utility for handling script execution
class PythonBridge {
  constructor() {
    this.isElectron = typeof window !== 'undefined' && window.require;
    this.ipcRenderer = this.isElectron ? window.require('electron').ipcRenderer : null;
  }

  async executeScript(scriptPath, args = []) {
    if (!this.isElectron || !this.ipcRenderer) {
      throw new Error('This application must be run in Electron environment to execute Python scripts');
    }

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
  }

  async executeTerminalAction(action, params = {}) {
    if (!this.isElectron || !this.ipcRenderer) {
      throw new Error('This application must be run in Electron environment for terminal operations');
    }

    try {
      const result = await this.ipcRenderer.invoke('execute-terminal-action', action, params);
      return result;
    } catch (error) {
      return {
        success: false,
        error: `Terminal action failed: ${error.message}`
      };
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

  async getDevices() {
    if (!this.isElectron || !this.ipcRenderer) {
      throw new Error('This application must be run in Electron environment');
    }

    try {
      const result = await this.ipcRenderer.invoke('get-devices');
      return result.error ? [] : result;
    } catch (error) {
      console.error('Error loading devices:', error);
      throw new Error('Failed to load devices from Python backend');
    }
  }

  async saveDevice(deviceData) {
    if (!this.isElectron || !this.ipcRenderer) {
      throw new Error('This application must be run in Electron environment');
    }

    try {
      const result = await this.ipcRenderer.invoke('save-device', deviceData);
      return result;
    } catch (error) {
      return { success: false, error: error.message };
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