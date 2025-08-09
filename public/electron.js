const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');

let mainWindow;
let pythonProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    },
    icon: path.join(__dirname, 'assets', 'icon.png'),
    titleBarStyle: 'default',
    show: false
  });

  const isDev = process.env.NODE_ENV === 'development';
  
  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../build/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    if (pythonProcess) {
      pythonProcess.kill();
    }
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Enhanced Python bridge functions
ipcMain.handle('execute-python-script', async (event, scriptPath, args = []) => {
  return new Promise((resolve, reject) => {
    // Try different Python executables based on platform
    let pythonPath;
    if (process.platform === 'win32') {
      pythonPath = 'python'; // Windows typically uses 'python'
    } else {
      pythonPath = 'python3'; // Unix-like systems prefer 'python3'
    }
    
    const fullScriptPath = path.join(__dirname, '..', scriptPath);
    
    // Check if script file exists
    if (!fs.existsSync(fullScriptPath)) {
      reject({
        success: false,
        error: `Python script not found: ${fullScriptPath}`,
        output: '',
        exitCode: -1
      });
      return;
    }
    
    // Enhanced argument processing for configuration data
    const processedArgs = args.map(arg => {
      if (typeof arg === 'object') {
        return JSON.stringify(arg);
      }
      return arg.toString();
    });
    
    console.log(`Executing: ${pythonPath} ${fullScriptPath} ${processedArgs.join(' ')}`);
    
    const pythonProcess = spawn(pythonPath, [fullScriptPath, ...processedArgs], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let error = '';

    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
      console.log('Python stdout:', data.toString());
    });

    pythonProcess.stderr.on('data', (data) => {
      error += data.toString();
      console.log('Python stderr:', data.toString());
    });

    pythonProcess.on('error', (err) => {
      console.error('Python process error:', err);
      reject({ 
        success: false, 
        error: `Failed to start Python process: ${err.message}. Make sure Python is installed and in PATH.`,
        output: '',
        exitCode: -1
      });
    });

    pythonProcess.on('close', (code) => {
      console.log(`Python process exited with code: ${code}`);
      if (code === 0) {
        resolve({ 
          success: true, 
          output, 
          error,
          exitCode: code
        });
      } else {
        reject({ 
          success: false, 
          output, 
          error, 
          exitCode: code 
        });
      }
    });
  });
});

// Terminal interface handler
ipcMain.handle('execute-terminal-action', async (event, action, params = {}) => {
  return new Promise((resolve, reject) => {
    let pythonPath;
    if (process.platform === 'win32') {
      pythonPath = 'python';
    } else {
      pythonPath = 'python3';
    }
    
    const scriptPath = path.join(__dirname, '..', 'terminal_interface', 'terminal_manager.py');
    
    // Check if script exists
    if (!fs.existsSync(scriptPath)) {
      resolve({
        success: false,
        error: `Terminal script not found: ${scriptPath}`
      });
      return;
    }
    
    // Prepare arguments
    const args = [action];
    if (Object.keys(params).length > 0) {
      args.push(JSON.stringify(params));
    }
    
    console.log(`Executing terminal action: ${pythonPath} ${scriptPath} ${args.join(' ')}`);
    
    const pythonProcess = spawn(pythonPath, [scriptPath, ...args], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let error = '';

    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
      console.log('Terminal stdout:', data.toString());
    });

    pythonProcess.stderr.on('data', (data) => {
      error += data.toString();
      console.log('Terminal stderr:', data.toString());
    });

    pythonProcess.on('error', (err) => {
      console.error('Terminal process error:', err);
      resolve({
        success: false,
        error: `Failed to start terminal process: ${err.message}`
      });
    });

    pythonProcess.on('close', (code) => {
      console.log(`Terminal process exited with code: ${code}`);
      try {
        const result = output.trim() ? JSON.parse(output) : { success: false, error: 'No output received' };
        resolve(result);
      } catch (e) {
        console.error('Failed to parse terminal output:', e);
        resolve({
          success: false,
          error: `Failed to parse terminal response: ${e.message}`,
          raw_output: output,
          raw_error: error
        });
      }
    });
  });
});

ipcMain.handle('get-devices', async () => {
  try {
    const result = await new Promise((resolve, reject) => {
      let pythonPath;
      if (process.platform === 'win32') {
        pythonPath = 'python';
      } else {
        pythonPath = 'python3';
      }
      
      const scriptPath = path.join(__dirname, '..', 'python_bridge', 'device_manager.py');
      
      // Check if script exists
      if (!fs.existsSync(scriptPath)) {
        reject({ error: `Device manager script not found: ${scriptPath}` });
        return;
      }
      
      console.log(`Getting devices: ${pythonPath} ${scriptPath} list_devices`);
      
      const pythonProcess = spawn(pythonPath, [scriptPath, 'list_devices'], {
        cwd: path.join(__dirname, '..'),
        env: { ...process.env },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
        console.log('Device manager stdout:', data.toString());
      });

      pythonProcess.stderr.on('data', (data) => {
        error += data.toString();
        console.log('Device manager stderr:', data.toString());
      });

      pythonProcess.on('error', (err) => {
        console.error('Device manager process error:', err);
        reject({ error: `Failed to start device manager: ${err.message}` });
      });

      pythonProcess.on('close', (code) => {
        console.log(`Device manager process exited with code: ${code}`);
        if (code === 0) {
          try {
            const devices = output.trim() ? JSON.parse(output) : [];
            resolve(devices);
          } catch (e) {
            console.error('Failed to parse device data:', e);
            reject({ error: 'Failed to parse device data' });
          }
        } else {
          reject({ error: error || 'Device manager script failed' });
        }
      });
    });

    return result;
  } catch (error) {
    return { error: error.message };
  }
});

ipcMain.handle('save-device', async (event, deviceData) => {
  try {
    const result = await new Promise((resolve, reject) => {
      let pythonPath;
      if (process.platform === 'win32') {
        pythonPath = 'python';
      } else {
        pythonPath = 'python3';
      }
      
      const scriptPath = path.join(__dirname, '..', 'python_bridge', 'device_manager.py');
      
      // Check if script exists
      if (!fs.existsSync(scriptPath)) {
        reject({ success: false, error: `Device manager script not found: ${scriptPath}` });
        return;
      }
      
      console.log(`Saving device: ${pythonPath} ${scriptPath} save_device`);
      
      const pythonProcess = spawn(pythonPath, [scriptPath, 'save_device', JSON.stringify(deviceData)], {
        cwd: path.join(__dirname, '..'),
        env: { ...process.env },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
        console.log('Save device stdout:', data.toString());
      });

      pythonProcess.stderr.on('data', (data) => {
        error += data.toString();
        console.log('Save device stderr:', data.toString());
      });

      pythonProcess.on('error', (err) => {
        console.error('Save device process error:', err);
        reject({ success: false, error: `Failed to start save device process: ${err.message}` });
      });

      pythonProcess.on('close', (code) => {
        console.log(`Save device process exited with code: ${code}`);
        if (code === 0) {
          resolve({ success: true, message: output.trim() || 'Device saved successfully' });
        } else {
          reject({ success: false, error: error || 'Failed to save device' });
        }
      });
    });

    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('show-save-dialog', async (event, options) => {
  const result = await dialog.showSaveDialog(mainWindow, options);
  return result;
});

ipcMain.handle('show-open-dialog', async (event, options) => {
  const result = await dialog.showOpenDialog(mainWindow, options);
  return result;
});