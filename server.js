const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const bodyParser = require('body-parser');
const expressWs = require('express-ws');
const compression = require('compression');
const simpleGit = require('simple-git');

const app = express();
expressWs(app);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'beratech-secret-key';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/beratech', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const AppSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  gitUrl: { type: String, required: true },
  status: { type: String, default: 'stopped' }, // stopped, running, deploying
  createdAt: { type: Date, default: Date.now },
  port: { type: Number, unique: true }
});

const LogSchema = new mongoose.Schema({
  app: { type: mongoose.Schema.Types.ObjectId, ref: 'App', required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, default: 'info' } // info, error, build
});

const User = mongoose.model('User', UserSchema);
const App = mongoose.model('App', AppSchema);
const Log = mongoose.model('Log', LogSchema);

// In-memory process management
const runningProcesses = new Map();
const appPorts = new Map();
let nextPort = 4000;

// Middleware
app.use(compression());
app.use(morgan('combined'));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static('.'));

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: false });
    res.json({ message: 'User created successfully', token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: false });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/create-app', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'App name required' });
    }
    
    const existingApp = await App.findOne({ name });
    if (existingApp) {
      return res.status(400).json({ error: 'App name already exists' });
    }
    
    const port = nextPort++;
    const gitUrl = `http://${req.get('host')}/git/${name}.git`;
    
    const app = new App({
      name,
      owner: req.user._id,
      gitUrl,
      port
    });
    
    await app.save();
    
    // Create app directory
    const appDir = path.join(__dirname, 'apps', name);
    if (!fs.existsSync(appDir)) {
      fs.mkdirSync(appDir, { recursive: true });
    }
    
    res.json({ 
      message: 'App created successfully', 
      app: { 
        name: app.name, 
        gitUrl: app.gitUrl,
        status: app.status 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/myapps', authenticateToken, async (req, res) => {
  try {
    const apps = await App.find({ owner: req.user._id });
    res.json({ apps });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/start/:id', authenticateToken, async (req, res) => {
  try {
    const app = await App.findOne({ _id: req.params.id, owner: req.user._id });
    if (!app) {
      return res.status(404).json({ error: 'App not found' });
    }
    
    if (app.status === 'running') {
      return res.json({ message: 'App is already running' });
    }
    
    const appDir = path.join(__dirname, 'apps', app.name);
    
    // Check if app has been deployed
    if (!fs.existsSync(path.join(appDir, 'package.json'))) {
      return res.status(400).json({ error: 'App not deployed yet' });
    }
    
    // Start the app
    await startApp(app);
    
    res.json({ message: 'App started successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/stop/:id', authenticateToken, async (req, res) => {
  try {
    const app = await App.findOne({ _id: req.params.id, owner: req.user._id });
    if (!app) {
      return res.status(404).json({ error: 'App not found' });
    }
    
    if (app.status !== 'running') {
      return res.json({ message: 'App is not running' });
    }
    
    // Stop the app
    await stopApp(app);
    
    res.json({ message: 'App stopped successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/logs/:id', authenticateToken, async (req, res) => {
  try {
    const app = await App.findOne({ _id: req.params.id, owner: req.user._id });
    if (!app) {
      return res.status(404).json({ error: 'App not found' });
    }
    
    const logs = await Log.find({ app: app._id }).sort({ timestamp: -1 }).limit(100);
    res.json({ logs: logs.reverse() });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Git HTTP server for receiving pushes
app.post('/git/:appName.git/*', async (req, res) => {
  try {
    const appName = req.params.appName;
    const app = await App.findOne({ name: appName });
    
    if (!app) {
      return res.status(404).json({ error: 'App not found' });
    }
    
    // In a real implementation, you would use proper git HTTP authentication
    // For simplicity, we'll assume authentication is handled via the web interface
    
    res.setHeader('Content-Type', 'application/json');
    res.json({ message: 'Git push received' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Handle git receive-pack (git push)
app.post('/git/:appName.git/git-receive-pack', bodyParser.text({ type: '*/*' }), async (req, res) => {
  try {
    const appName = req.params.appName;
    const app = await App.findOne({ name: appName });
    
    if (!app) {
      return res.status(404).send('App not found');
    }
    
    // Update app status to deploying
    app.status = 'deploying';
    await app.save();
    
    const appDir = path.join(__dirname, 'apps', appName);
    
    // Initialize git repo if it doesn't exist
    if (!fs.existsSync(path.join(appDir, '.git'))) {
      fs.mkdirSync(appDir, { recursive: true });
      const git = simpleGit(appDir);
      await git.init();
    }
    
    // Write the received pack file
    const packPath = path.join(appDir, 'git-receive-pack');
    fs.writeFileSync(packPath, req.body);
    
    // Update the git repo
    const git = simpleGit(appDir);
    await git.raw(['receive-pack', '--stateless-rpc', appDir]);
    
    // Checkout the latest code
    await git.checkout('main').catch(() => git.checkout('master'));
    
    // Add log entry
    const log = new Log({
      app: app._id,
      message: 'Git push received, starting build process',
      type: 'info'
    });
    await log.save();
    
    // Build and deploy the app
    await buildAndDeployApp(app);
    
    res.setHeader('Content-Type', 'application/x-git-receive-pack-result');
    res.send('0000000000000000000000000000000000000000 capabilities^{}\x00report-status\n0000');
  } catch (error) {
    console.error('Git receive error:', error);
    res.status(500).send('Internal server error');
  }
});

// Serve deployed apps
app.get('/apps/:appName', (req, res) => {
  const appName = req.params.appName;
  const appDir = path.join(__dirname, 'apps', appName);
  
  // Check if app exists and is running
  if (!fs.existsSync(appDir)) {
    return res.status(404).send('App not found');
  }
  
  // In a production environment, you would proxy requests to the app's port
  // For simplicity, we'll just serve a placeholder
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>${appName} - BeraTech Deployment</title>
      <style>
        body { 
          background-color: #0d1117; 
          color: #00ffcc; 
          font-family: Arial, sans-serif; 
          text-align: center; 
          padding: 50px; 
        }
        h1 { color: #00ffcc; }
      </style>
    </head>
    <body>
      <h1>${appName} is running on BeraTech</h1>
      <p>Your application has been successfully deployed.</p>
    </body>
    </html>
  `);
});

// WebSocket for real-time logs
app.ws('/logs/:appId', async (ws, req) => {
  const token = req.query.token;
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      ws.close(1008, 'Invalid token');
      return;
    }
    
    const app = await App.findOne({ _id: req.params.appId, owner: user._id });
    
    if (!app) {
      ws.close(1008, 'App not found');
      return;
    }
    
    // Send recent logs
    const logs = await Log.find({ app: app._id }).sort({ timestamp: -1 }).limit(50);
    logs.reverse().forEach(log => {
      ws.send(JSON.stringify(log));
    });
    
    // Watch for new logs (simplified implementation)
    const logStream = Log.watch([{ 
      $match: { 
        'fullDocument.app': app._id 
      } 
    }], { 
      fullDocument: 'updateLookup' 
    });
    
    logStream.on('change', (change) => {
      ws.send(JSON.stringify(change.fullDocument));
    });
    
    ws.on('close', () => {
      logStream.close();
    });
  } catch (error) {
    ws.close(1008, 'Authentication error');
  }
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Helper functions
async function buildAndDeployApp(app) {
  const appDir = path.join(__dirname, 'apps', app.name);
  
  try {
    // Add build log
    const buildLog = new Log({
      app: app._id,
      message: 'Starting build process...',
      type: 'build'
    });
    await buildLog.save();
    
    // Run npm install
    await new Promise((resolve, reject) => {
      const installProcess = exec('npm install', { cwd: appDir }, (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
      
      // Log install output
      installProcess.stdout.on('data', async (data) => {
        const log = new Log({
          app: app._id,
          message: data.toString(),
          type: 'build'
        });
        await log.save();
      });
      
      installProcess.stderr.on('data', async (data) => {
        const log = new Log({
          app: app._id,
          message: data.toString(),
          type: 'error'
        });
        await log.save();
      });
    });
    
    // Add build success log
    const successLog = new Log({
      app: app._id,
      message: 'Build completed successfully',
      type: 'info'
    });
    await successLog.save();
    
    // Start the app if it was running before
    if (app.status === 'running') {
      await startApp(app);
    } else {
      app.status = 'stopped';
      await app.save();
    }
  } catch (error) {
    // Add error log
    const errorLog = new Log({
      app: app._id,
      message: `Build failed: ${error.message}`,
      type: 'error'
    });
    await errorLog.save();
    
    app.status = 'stopped';
    await app.save();
  }
}

async function startApp(app) {
  // Stop app if already running
  if (runningProcesses.has(app.name)) {
    await stopApp(app);
  }
  
  const appDir = path.join(__dirname, 'apps', app.name);
  
  try {
    // Determine start command
    let startCommand = 'node index.js';
    if (fs.existsSync(path.join(appDir, 'package.json'))) {
      const packageJson = JSON.parse(fs.readFileSync(path.join(appDir, 'package.json'), 'utf8'));
      if (packageJson.scripts && packageJson.scripts.start) {
        startCommand = 'npm start';
      }
    }
    
    // Start the app
    const childProcess = spawn(startCommand.split(' ')[0], startCommand.split(' ').slice(1), {
      cwd: appDir,
      env: { ...process.env, PORT: app.port }
    });
    
    runningProcesses.set(app.name, childProcess);
    appPorts.set(app.name, app.port);
    
    // Update app status
    app.status = 'running';
    await app.save();
    
    // Add log
    const log = new Log({
      app: app._id,
      message: `App started on port ${app.port}`,
      type: 'info'
    });
    await log.save();
    
    // Capture app output
    childProcess.stdout.on('data', async (data) => {
      const log = new Log({
        app: app._id,
        message: data.toString(),
        type: 'info'
      });
      await log.save();
    });
    
    childProcess.stderr.on('data', async (data) => {
      const log = new Log({
        app: app._id,
        message: data.toString(),
        type: 'error'
      });
      await log.save();
    });
    
    childProcess.on('close', async (code) => {
      runningProcesses.delete(app.name);
      appPorts.delete(app.name);
      
      if (app.status === 'running') {
        app.status = 'stopped';
        await app.save();
        
        const log = new Log({
          app: app._id,
          message: `App process exited with code ${code}`,
          type: 'error'
        });
        await log.save();
      }
    });
  } catch (error) {
    const log = new Log({
      app: app._id,
      message: `Failed to start app: ${error.message}`,
      type: 'error'
    });
    await log.save();
    
    app.status = 'stopped';
    await app.save();
  }
}

async function stopApp(app) {
  const childProcess = runningProcesses.get(app.name);
  
  if (childProcess) {
    childProcess.kill();
    runningProcesses.delete(app.name);
    appPorts.delete(app.name);
  }
  
  app.status = 'stopped';
  await app.save();
  
  // Add log
  const log = new Log({
    app: app._id,
    message: 'App stopped',
    type: 'info'
  });
  await log.save();
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down...');
  
  // Stop all running apps
  for (const [appName, process] of runningProcesses.entries()) {
    process.kill();
  }
  
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`BeraTech Deployment Site running on port ${PORT}`);
  
  // Create apps directory if it doesn't exist
  const appsDir = path.join(__dirname, 'apps');
  if (!fs.existsSync(appsDir)) {
    fs.mkdirSync(appsDir, { recursive: true });
  }
});
