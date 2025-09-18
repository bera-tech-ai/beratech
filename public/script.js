const socket = io();
let currentApp = null;

// DOM elements
const registerBtn = document.getElementById('register-btn');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const dashboard = document.getElementById('dashboard');
const appsList = document.getElementById('apps-list');
const appDetails = document.getElementById('app-details');
const detailAppName = document.getElementById('detail-app-name');
const detailAppUrl = document.getElementById('detail-app-url');
const logsContainer = document.getElementById('logs');

// Event listeners
registerBtn.addEventListener('click', () => {
  registerForm.style.display = 'block';
  loginForm.style.display = 'none';
});

loginBtn.addEventListener('click', () => {
  loginForm.style.display = 'block';
  registerForm.style.display = 'none';
});

document.getElementById('register-submit').addEventListener('click', register);
document.getElementById('login-submit').addEventListener('click', login);
logoutBtn.addEventListener('click', logout);
document.getElementById('create-app').addEventListener('click', createApp);

// Check if user is logged in
if (localStorage.getItem('token')) {
  showDashboard();
  loadApps();
}

// Authentication functions
async function register() {
  const username = document.getElementById('register-username').value;
  const password = document.getElementById('register-password').value;

  try {
    const response = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (response.ok) {
      alert('Registration successful. Please login.');
      registerForm.style.display = 'none';
    } else {
      alert('Registration failed');
    }
  } catch (error) {
    console.error('Registration error:', error);
  }
}

async function login() {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('token', data.token);
      showDashboard();
      loadApps();
    } else {
      alert('Login failed');
    }
  } catch (error) {
    console.error('Login error:', error);
  }
}

function logout() {
  localStorage.removeItem('token');
  document.getElementById('auth-forms').style.display = 'block';
  dashboard.style.display = 'none';
  logoutBtn.style.display = 'none';
  loginBtn.style.display = 'inline-block';
  registerBtn.style.display = 'inline-block';
}

function showDashboard() {
  document.getElementById('auth-forms').style.display = 'none';
  dashboard.style.display = 'block';
  logoutBtn.style.display = 'inline-block';
  loginBtn.style.display = 'none';
  registerBtn.style.display = 'none';
}

// App management functions
async function loadApps() {
  try {
    const response = await fetch('/apps', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (response.ok) {
      const apps = await response.json();
      renderApps(apps);
    }
  } catch (error) {
    console.error('Error loading apps:', error);
  }
}

function renderApps(apps) {
  appsList.innerHTML = '';
  apps.forEach(app => {
    const appElement = document.createElement('div');
    appElement.className = 'app-item';
    appElement.innerHTML = `
      <h3>${app.name}</h3>
      <p>Status: ${app.status}</p>
      <p>URL: <a href="https://${app.subdomain}" target="_blank">${app.subdomain}</a></p>
      <button class="view-logs" data-app="${app.name}">View Logs</button>
    `;
    appsList.appendChild(appElement);
  });

  // Add event listeners to view logs buttons
  document.querySelectorAll('.view-logs').forEach(button => {
    button.addEventListener('click', (e) => {
      const appName = e.target.getAttribute('data-app');
      showAppDetails(appName);
    });
  });
}

async function createApp() {
  const appName = document.getElementById('app-name').value;
  
  try {
    const response = await fetch('/apps', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ name: appName })
    });

    if (response.ok) {
      loadApps();
      document.getElementById('app-name').value = '';
    } else {
      alert('Error creating app');
    }
  } catch (error) {
    console.error('Error creating app:', error);
  }
}

function showAppDetails(appName) {
  currentApp = appName;
  appDetails.style.display = 'block';
  detailAppName.textContent = appName;
  
  // Find the app URL
  const apps = document.querySelectorAll('.app-item');
  apps.forEach(app => {
    if (app.querySelector('h3').textContent === appName) {
      const url = app.querySelector('a').href;
      detailAppUrl.href = url;
      detailAppUrl.textContent = url;
    }
  });
  
  // Clear logs and listen for new ones
  logsContainer.innerHTML = '';
  socket.emit('join-app', appName);
}

// Socket.io for logs
socket.on('log', (data) => {
  if (currentApp) {
    const logEntry = document.createElement('div');
    logEntry.textContent = data;
    logsContainer.appendChild(logEntry);
    logsContainer.scrollTop = logsContainer.scrollHeight;
  }
});
