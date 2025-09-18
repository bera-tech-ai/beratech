require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { spawn } = require('child_process');
const fs = require('fs-extra');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const pm2 = require('pm2');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(express.json());
app.use(express.static('public'));

// MongoDB Models
const User = require('./models/User');
const App = require('./models/App');

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User created');
  } catch (error) {
    res.status(500).send('Error creating user');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

app.post('/apps', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    const app = new App({
      name,
      userId: req.user.userId,
      port: await getAvailablePort(),
      subdomain: `${name}.bera.karenbishop.online`,
    });
    await app.save();
    res.json(app);
  } catch (error) {
    res.status(500).send('Error creating app');
  }
});

app.get('/apps', authenticateToken, async (req, res) => {
  try {
    const apps = await App.find({ userId: req.user.userId });
    res.json(apps);
  } catch (error) {
    res.status(500).send('Error fetching apps');
  }
});

// Git receive-pack handler for git push
app.post('/git/:appName', authenticateToken, async (req, res) => {
  try {
    const { appName } = req.params;
    const app = await App.findOne({ name: appName, userId: req.user.userId });
    
    if (!app) return res.status(404).send('App not found');
    
    // Extract git repo and deploy
    await handleGitPush(app);
    res.send('Deployment started');
  } catch (error) {
    res.status(500).send('Error deploying app');
  }
});

// WebSocket for logs
io.on('connection', (socket) => {
  socket.on('join-app', (appName) => {
    socket.join(appName);
  });
});

// Helper functions
async function getAvailablePort() {
  // Implementation to find an available port
  return 4000 + Math.floor(Math.random() * 1000);
}

async function handleGitPush(app) {
  const appDir = path.join(__dirname, 'apps', app.userId.toString(), app.name);
  await fs.ensureDir(appDir);
  
  // Extract git repository and build
  // This is a simplified version - in reality you'd need a proper git receiver
  await buildAndDeployApp(app, appDir);
}

async function buildAndDeployApp(app, appDir) {
  try {
    // Install dependencies
    const installProcess = spawn('npm', ['install'], { cwd: appDir });
    
    installProcess.stdout.on('data', (data) => {
      io.to(app.name).emit('log', data.toString());
    });
    
    installProcess.stderr.on('data', (data) => {
      io.to(app.name).emit('log', data.toString());
    });
    
    await new Promise((resolve, reject) => {
      installProcess.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`npm install failed with code ${code}`));
      });
    });
    
    // Start with PM2
    pm2.connect((err) => {
      if (err) throw err;
      
      pm2.start({
        name: app.name,
        script: 'npm',
        args: ['start'],
        cwd: appDir,
        env: {
          PORT: app.port,
          NODE_ENV: 'production'
        }
      }, (err, apps) => {
        pm2.disconnect();
        if (err) throw err;
        
        // Stream logs
        pm2.launchBus((err, bus) => {
          bus.on('log:out', (packet) => {
            if (packet.process.name === app.name) {
              io.to(app.name).emit('log', packet.data);
            }
          });
          
          bus.on('log:err', (packet) => {
            if (packet.process.name === app.name) {
              io.to(app.name).emit('log', packet.data);
            }
          });
        });
      });
    });
    
    // Update app status
    app.status = 'running';
    await app.save();
    
  } catch (error) {
    app.status = 'failed';
    await app.save();
    io.to(app.name).emit('log', `Deployment failed: ${error.message}`);
  }
}

server.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
