// Global variables
let currentUser = null;
let socket = null;
let uploadedFiles = [];

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    checkAuthStatus();
});

function initializeApp() {
    // Initialize Socket.io
    socket = io();
    
    // Setup socket event listeners
    socket.on('messageHistory', (messages) => {
        displayMessageHistory(messages);
    });
    
    socket.on('newMessage', (message) => {
        displayNewMessage(message);
    });
    
    // Check for existing session
    checkAuthStatus();
}

function setupEventListeners() {
    // Auth form toggles
    document.getElementById('showRegister').addEventListener('click', showRegisterForm);
    document.getElementById('showLogin').addEventListener('click', showLoginForm);
    
    // Auth form submissions
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerForm').addEventListener('submit', handleRegister);
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab(e.currentTarget.dataset.tab);
        });
    });
    
    // Chat functionality
    document.getElementById('send-btn').addEventListener('click', sendMessage);
    document.getElementById('message-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
    
    // File upload
    document.getElementById('file-btn').addEventListener('click', () => {
        document.getElementById('file-upload').click();
    });
    
    document.getElementById('file-upload').addEventListener('change', handleFileSelect);
    
    // AI functionality
    document.getElementById('ask-ai-btn').addEventListener('click', askAI);
    document.getElementById('ai-question').addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            askAI();
        }
    });
    
    // Project functionality
    document.getElementById('new-project-btn').addEventListener('click', showProjectModal);
    document.getElementById('project-form').addEventListener('submit', handleProjectSubmit);
    document.getElementById('cancel-project').addEventListener('click', hideProjectModal);
    document.querySelector('.close').addEventListener('click', hideProjectModal);
    
    // Modal close on outside click
    document.getElementById('project-modal').addEventListener('click', (e) => {
        if (e.target.id === 'project-modal') hideProjectModal();
    });
}

// Authentication Functions
async function checkAuthStatus() {
    try {
        const response = await fetch('/auth/check');
        const data = await response.json();
        
        if (data.loggedIn) {
            currentUser = { username: data.username };
            showMainApp(data.username);
        } else {
            showAuthSection();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showAuthSection();
    }
}

function showAuthSection() {
    document.getElementById('auth-section').classList.add('active');
    document.getElementById('main-app').classList.remove('active');
}

function showMainApp(username) {
    document.getElementById('auth-section').classList.remove('active');
    document.getElementById('main-app').classList.add('active');
    
    document.getElementById('welcome-user').textContent = `Welcome, ${username}`;
    document.getElementById('sidebar-username').textContent = username;
    
    // Load initial data
    loadProjects();
}

function showLoginForm(e) {
    if (e) e.preventDefault();
    document.getElementById('login-form').classList.add('active');
    document.getElementById('register-form').classList.remove('active');
}

function showRegisterForm(e) {
    if (e) e.preventDefault();
    document.getElementById('register-form').classList.add('active');
    document.getElementById('login-form').classList.remove('active');
}

async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            showMainApp(data.user.username);
        } else {
            alert(data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    
    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            showMainApp(data.user.username);
        } else {
            alert(data.error || 'Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed. Please try again.');
    }
}

async function handleLogout() {
    try {
        await fetch('/auth/logout', { method: 'POST' });
        currentUser = null;
        showAuthSection();
        // Reset forms
        document.getElementById('loginForm').reset();
        document.getElementById('registerForm').reset();
        showLoginForm();
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Tab Navigation
function switchTab(tabName) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load tab-specific data
    if (tabName === 'projects') {
        loadProjects();
    }
}

// Chat Functions
function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const text = messageInput.value.trim();
    
    if (!text && uploadedFiles.length === 0) return;
    
    const messageData = {
        username: currentUser.username,
        text: text,
        file: uploadedFiles.length > 0 ? uploadedFiles[0] : null // For demo, send first file only
    };
    
    socket.emit('sendMessage', messageData);
    
    // Clear input and reset file upload
    messageInput.value = '';
    clearFileUpload();
}

function displayMessageHistory(messages) {
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.innerHTML = '';
    
    messages.forEach(message => {
        displayNewMessage(message);
    });
}

function displayNewMessage(message) {
    const chatMessages = document.getElementById('chat-messages');
    const messageElement = document.createElement('div');
    
    const isOwnMessage = message.username === currentUser.username;
    messageElement.className = `message ${isOwnMessage ? 'own' : 'other'}`;
    
    const time = new Date(message.timestamp).toLocaleTimeString();
    
    let fileHtml = '';
    if (message.file) {
        fileHtml = `
            <div class="file-preview">
                <i class="fas fa-paperclip"></i>
                <a href="/uploads/${message.file.filename}" download="${message.file.originalname}">
                    ${message.file.originalname}
                </a>
            </div>
        `;
    }
    
    messageElement.innerHTML = `
        <div class="message-header">
            <span class="message-username">${message.username}</span>
            <span class="message-time">${time}</span>
        </div>
        ${fileHtml}
        <div class="message-content">${escapeHtml(message.text)}</div>
    `;
    
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// File Upload Functions
function handleFileSelect(e) {
    const files = e.target.files;
    uploadedFiles = Array.from(files);
    
    const fileNames = document.getElementById('file-names');
    fileNames.textContent = uploadedFiles.map(f => f.name).join(', ');
    
    // Upload files to server
    uploadFiles(uploadedFiles);
}

async function uploadFiles(files) {
    const formData = new FormData();
    files.forEach(file => {
        formData.append('files', file);
    });
    
    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        if (data.success) {
            uploadedFiles = data.files;
        }
    } catch (error) {
        console.error('File upload error:', error);
        alert('File upload failed');
    }
}

function clearFileUpload() {
    document.getElementById('file-upload').value = '';
    document.getElementById('file-names').textContent = '';
    uploadedFiles = [];
}

// AI Functions
async function askAI() {
    const questionInput = document.getElementById('ai-question');
    const question = questionInput.value.trim();
    
    if (!question) return;
    
    // Add user question to chat
    addAIMessage(question, 'user');
    questionInput.value = '';
    
    try {
        const response = await fetch('/devs-ai', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question })
        });
        
        const data = await response.json();
        
        if (data.success) {
            addAIMessage(data.answer, 'bot');
        } else {
            addAIMessage('Sorry, I encountered an error. Please try again.', 'bot');
        }
    } catch (error) {
        console.error('AI request error:', error);
        addAIMessage('Sorry, I\'m having trouble connecting. Please check your connection.', 'bot');
    }
}

function addAIMessage(content, type) {
    const aiChat = document.getElementById('ai-chat');
    const messageElement = document.createElement('div');
    
    messageElement.className = `ai-message ${type}`;
    messageElement.innerHTML = `
        <div class="message-content">${formatAIMessage(content)}</div>
    `;
    
    aiChat.appendChild(messageElement);
    aiChat.scrollTop = aiChat.scrollHeight;
}

function formatAIMessage(content) {
    // Simple formatting for code blocks
    return content.replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>');
}

// Project Functions
function showProjectModal() {
    document.getElementById('project-modal').classList.add('active');
}

function hideProjectModal() {
    document.getElementById('project-modal').classList.remove('active');
    document.getElementById('project-form').reset();
}

async function handleProjectSubmit(e) {
    e.preventDefault();
    
    const title = document.getElementById('project-title').value;
    const description = document.getElementById('project-description').value;
    const code = document.getElementById('project-code').value;
    
    try {
        const response = await fetch('/projects', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, description, code })
        });
        
        const data = await response.json();
        
        if (data.success) {
            hideProjectModal();
            loadProjects();
        } else {
            alert(data.error || 'Failed to create project');
        }
    } catch (error) {
        console.error('Project creation error:', error);
        alert('Failed to create project');
    }
}

async function loadProjects() {
    try {
        const response = await fetch('/projects');
        const projects = await response.json();
        
        displayProjects(projects);
    } catch (error) {
        console.error('Failed to load projects:', error);
    }
}

function displayProjects(projects) {
    const container = document.getElementById('projects-container');
    
    if (projects.length === 0) {
        container.innerHTML = `
            <div class="no-projects">
                <p>No projects shared yet. Be the first to share your work!</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = projects.map(project => `
        <div class="project-card">
            <div class="project-header">
                <div>
                    <h3 class="project-title">${escapeHtml(project.title)}</h3>
                    <p class="project-author">by ${escapeHtml(project.author)}</p>
                </div>
            </div>
            <p class="project-description">${escapeHtml(project.description)}</p>
            ${project.code ? `
                <pre class="project-code"><code class="language-javascript">${escapeHtml(project.code)}</code></pre>
            ` : ''}
            <div class="project-actions">
                <button class="btn btn-outline" onclick="viewProject('${project.id}')">
                    <i class="fas fa-comment"></i> Comment
                </button>
            </div>
        </div>
    `).join('');
    
    // Apply syntax highlighting
    Prism.highlightAll();
}

function viewProject(projectId) {
    // For demo purposes, just show an alert
    alert('Comment functionality would be implemented here!');
}

// Utility Functions
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
                           }
