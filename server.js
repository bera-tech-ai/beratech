const express = require('express');
const session = require('express-session');
const axios = require('axios');
const simpleGit = require('simple-git');
const Docker = require('dockerode');
const fs = require('fs-extra');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS directly
}));

// Docker client
const docker = new Docker();

// Ensure logs directory exists
const logsDir = '/data/logs';
fs.ensureDirSync(logsDir);

// GitHub OAuth configuration
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback';

// Routes

// Redirect to GitHub OAuth
app.get('/auth/github', (req, res) => {
  const redirectUri = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(GITHUB_CALLBACK_URL)}&scope=repo,user`;
  res.redirect(redirectUri);
});

// GitHub OAuth callback
app.get('/auth/github/callback', async (req, res) => {
  const { code } = req.query;

  try {
    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: GITHUB_CALLBACK_URL
    }, {
      headers: { Accept: 'application/json' }
    });

    const { access_token } = tokenResponse.data;
    req.session.githubToken = access_token;
    
    // Redirect to dashboard
    res.redirect('/');
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).send('Authentication failed');
  }
});

// Get user repositories
app.get('/api/repos', async (req, res) => {
  const token = req.session.githubToken;
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const response = await axios.get('https://api.github.com/user/repos', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3+json'
      },
      params: {
        sort: 'updated',
        direction: 'desc'
      }
    });

    res.json(response.data);
  } catch (error) {
    console.error('GitHub API error:', error);
    res.status(500).json({ error: 'Failed to fetch repositories' });
  }
});

// Deploy a repository
app.post('/api/deploy/:owner/:repo', async (req, res) => {
  const { owner, repo } = req.params;
  const token = req.session.githubToken;
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const repoUrl = `https://${token}@github.com/${owner}/${repo}.git`;
  const workDir = path.join('/data/repos', owner, repo);
  const logFile = path.join(logsDir, `${owner}-${repo}.log`);

  try {
    // Ensure working directory exists
    await fs.ensureDir(workDir);
    
    // Initialize log file
    await fs.writeFile(logFile, `Starting deployment for ${owner}/${repo} at ${new Date().toISOString()}\n`);

    // Clone or pull repository
    const git = simpleGit(workDir);
    const appendLog = (message) => fs.appendFile(logFile, message + '\n');
    
    appendLog(`Cloning repository from ${repoUrl.replace(token, '***')}`);
    
    if (await fs.pathExists(path.join(workDir, '.git'))) {
      await git.pull();
      appendLog('Repository pulled successfully');
    } else {
      await git.clone(repoUrl, workDir);
      appendLog('Repository cloned successfully');
    }

    // Build Docker image
    appendLog('Building Docker image...');
    const imageName = `app-${owner}-${repo}`.toLowerCase();
    
    const stream = await docker.buildImage({
      context: workDir,
      src: ['Dockerfile', '.dockerignore', 'package.json', 'app.js', 'index.js', 'server.js'].filter(f => 
        fs.existsSync(path.join(workDir, f))
      )
    }, { t: imageName });

    await new Promise((resolve, reject) => {
      docker.modem.followProgress(stream, (err, res) => err ? reject(err) : resolve(res));
    });
    
    appendLog('Docker image built successfully');

    // Stop and remove existing container if it exists
    try {
      const oldContainer = docker.getContainer(imageName);
      await oldContainer.stop();
      await oldContainer.remove();
      appendLog('Stopped and removed existing container');
    } catch (err) {
      // Container might not exist, which is fine
      appendLog('No existing container to remove');
    }

    // Find available port
    const usedPorts = new Set();
    const containers = await docker.listContainers({ all: true });
    containers.forEach(container => {
      container.Ports.forEach(port => {
        if (port.PublicPort) usedPorts.add(port.PublicPort);
      });
    });

    let port = 10000;
    while (usedPorts.has(port)) port++;
    
    appendLog(`Using port ${port} for deployment`);

    // Run container
    const container = await docker.createContainer({
      Image: imageName,
      name: imageName,
      ExposedPorts: { '3000/tcp': {} },
      HostConfig: {
        PortBindings: { '3000/tcp': [{ HostPort: port.toString() }] }
      }
    });

    await container.start();
    appendLog('Container started successfully');

    // Create nginx configuration
    const domain = process.env.DOMAIN || 'bera.karenbishop.online';
    const subdomain = `${repo}.${domain}`;
    
    const nginxConf = `
server {
    listen 80;
    server_name ${subdomain};
    
    location / {
        proxy_pass http://localhost:${port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;

    const nginxConfPath = `/etc/nginx/conf.d/${subdomain}.conf`;
    await fs.writeFile(nginxConfPath, nginxConf);
    appendLog(`Nginx configuration created at ${nginxConfPath}`);

    // Reload nginx
    const { exec } = require('child_process');
    exec('nginx -s reload', (error) => {
      if (error) {
        appendLog(`Error reloading nginx: ${error}`);
      } else {
        appendLog('Nginx reloaded successfully');
      }
    });

    // Request SSL certificate (this would typically be handled by certbot in the docker-compose)
    appendLog(`Deployment complete! Your app will be available at https://${subdomain} after SSL certificate is issued`);

    res.json({ 
      success: true, 
      message: 'Deployment started', 
      url: `https://${subdomain}`,
      logFile 
    });

  } catch (error) {
    console.error('Deployment error:', error);
    const errorMessage = `Deployment failed: ${error.message}`;
    await fs.appendFile(logFile, errorMessage + '\n');
    res.status(500).json({ error: errorMessage });
  }
});

// Get deployment logs
app.get('/api/logs/:owner/:repo', async (req, res) => {
  const { owner, repo } = req.params;
  const logFile = path.join(logsDir, `${owner}-${repo}.log`);
  
  try {
    if (await fs.pathExists(logFile)) {
      const logs = await fs.readFile(logFile, 'utf8');
      res.json({ logs });
    } else {
      res.json({ logs: 'No logs available' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to read logs' });
  }
});

// Get deployment status
app.get('/api/status/:owner/:repo', async (req, res) => {
  const { owner, repo } = req.params;
  const containerName = `app-${owner}-${repo}`.toLowerCase();
  
  try {
    const container = docker.getContainer(containerName);
    const info = await container.inspect();
    res.json({ status: info.State.Status, running: info.State.Running });
  } catch (error) {
    res.json({ status: 'not deployed', running: false });
  }
});

// Check authentication status
app.get('/api/user', (req, res) => {
  if (req.session.githubToken) {
    res.json({ authenticated: true });
  } else {
    res.json({ authenticated: false });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
