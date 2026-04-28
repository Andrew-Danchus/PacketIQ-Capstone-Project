const { app, BrowserWindow, dialog } = require("electron");
const { exec } = require("child_process");
const path = require("path");

let mainWindow;

const docker = '"C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"';

function runCommand(command, cwd) {
  return new Promise((resolve, reject) => {
    exec(command, { cwd }, (error, stdout, stderr) => {
      if (error) reject(stderr || error.message);
      else resolve(stdout);
    });
  });
}

async function startPacketIQ() {
  const projectRoot = app.isPackaged
    ? path.join(process.resourcesPath, "project")
    : path.join(__dirname, "..");

  try {
    await runCommand(`${docker} info`, projectRoot);
  } catch {
    dialog.showErrorBox(
      "Docker is not running",
      "Start Docker Desktop first, then reopen PacketIQ."
    );
    app.quit();
    return;
  }

  try {
    await runCommand(`${docker} compose down --remove-orphans`, projectRoot);
    await runCommand(`${docker} rm -f packetiq_ollama packetiq_db packetiq-capstone-project-backend-1 packetiq-capstone-project-frontend-1 project-backend-1 project-frontend-1`, projectRoot).catch(() => {});    
    await runCommand(`${docker} compose up --build -d`, projectRoot);
  } catch (err) {
    dialog.showErrorBox("PacketIQ Startup Error", String(err));
    app.quit();
    return;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1300,
    height: 850,
    title: "PacketIQ",
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadURL("http://localhost:5173");
}

app.whenReady().then(async () => {
  await startPacketIQ();

  setTimeout(() => {
    createWindow();
  }, 8000);
});

app.on("window-all-closed", () => {
  app.quit();
});