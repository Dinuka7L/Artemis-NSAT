const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

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
    const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
    const fullScriptPath = path.join(__dirname, '..', scriptPath);
    
    // Enhanced argument processing for configuration data
    const processedArgs = args.map(arg => {
      if (typeof arg === 'object') {
        return JSON.stringify(arg);
      }
      return arg.toString();
    });
    
    const pythonProcess = spawn(pythonPath, [fullScriptPath, ...processedArgs], {
      cwd: path.join(__dirname, '..')
    });

    let output = '';
    let error = '';

    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      error += data.toString();
    });

    pythonProcess.on('close', (code) => {
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

    pythonProcess.on('error', (err) => {
      reject({ 
        success: false, 
        error: err.message,
        output: '',
        exitCode: -1
      });
    });
  });
});

// Terminal interface handler
ipcMain.handle('execute-terminal-action', async (event, action, params = {}) => {
  return new Promise((resolve, reject) => {
    const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
    const scriptPath = path.join(__dirname, '..', 'terminal_interface', 'terminal_manager.py');
    
    // Prepare arguments
    const args = [action];
    if (Object.keys(params).length > 0) {
      args.push(JSON.stringify(params));
    }
    
    const pythonProcess = spawn(pythonPath, [scriptPath, ...args], {
      cwd: path.join(__dirname, '..')
    });

    let output = '';
    let error = '';

    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      error += data.toString();
    });

    pythonProcess.on('close', (code) => {
      try {
        const result = JSON.parse(output);
        resolve(result);
      } catch (e) {
        resolve({
          success: false,
          error: `Failed to parse terminal response: ${output}`,
          raw_output: output,
          raw_error: error
        });
      }
    });

    pythonProcess.on('error', (err) => {
      resolve({
        success: false,
        error: `Terminal process error: ${err.message}`
      });
    });
  });
});

ipcMain.handle('get-devices', async () => {
  try {
    const result = await new Promise((resolve, reject) => {
      const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
      const scriptPath = path.join(__dirname, '..', 'python_bridge', 'device_manager.py');
      
      const pythonProcess = spawn(pythonPath, [scriptPath, 'list_devices'], {
        cwd: path.join(__dirname, '..')
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
        error += data.toString();
      });

      pythonProcess.on('close', (code) => {
        if (code === 0) {
          try {
            const devices = JSON.parse(output);
            resolve(devices);
          } catch (e) {
            reject({ error: 'Failed to parse device data' });
          }
        } else {
          reject({ error });
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
      const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
      const scriptPath = path.join(__dirname, '..', 'python_bridge', 'device_manager.py');
      
      const pythonProcess = spawn(pythonPath, [scriptPath, 'save_device', JSON.stringify(deviceData)], {
        cwd: path.join(__dirname, '..')
      });

      let output = '';
      let error = '';

      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
        error += data.toString();
      });

      pythonProcess.on('close', (code) => {
        if (code === 0) {
          resolve({ success: true, message: output });
        } else {
          reject({ success: false, error });
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