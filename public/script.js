// Frontend JavaScript for authentication and UI interactions
const socket = io();

// DOM Elements
const authSection = document.getElementById('auth-section');
const authForms = document.getElementById('auth-forms');
const projectsSection = document.getElementById('projects-section');
const chatSection = document.getElementById('chat-section');
const aiSection = document.getElementById('ai-section');

// Check if user is logged in on page load
document.addEventListener('DOMContentLoaded', checkAuthStatus);

// Navigation
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const section = e.target.getAttribute('data-section');
        showSection(section);
    });
});

function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('main > section').forEach(section => {
        section.classList.add('hidden');
    });

    // Show the selected section
    document.getElementById(`${sectionName}-section`).classList.remove('hidden');
}

// Authentication Functions
function checkAuthStatus() {
    // This would typically check a cookie or token
    // For now, we'll assume user is logged out initially
    renderAuthForms();
}

function renderAuthForms() {
    authForms.innerHTML = `
        <div class="form-container">
            <h2>Login to Devs Place</h2>
            <form onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label for="login-email">Email:</label>
                    <input type="email" id="login-email" required>
                </div>
                <div class="form-group">
                    <label for="login-password">Password:</label>
                    <input type="password" id="login-password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <p>Don't have an account? <a href="#" onclick="showSignup()">Sign up</a></p>
        </div>
    `;
    authForms.classList.add('active');
}

function showSignup() {
    authForms.innerHTML = `
        <div class="form-container">
            <h2>Join Devs Place</h2>
            <form onsubmit="handleSignup(event)">
                <div class="form-group">
                    <label for="signup-username">Username:</label>
                    <input type="text" id="signup-username" required>
                </div>
                <div class="form-group">
                    <label for="signup-email">Email:</label>
                    <input type="email" id="signup-email" required>
                </div>
                <div class="form-group">
                    <label for="signup-password">Password:</label>
                    <input type="password" id="signup-password" required>
                </div>
                <button type="submit" class="btn">Sign Up</button>
            </form>
            <p>Already have an account? <a href="#" onclick="renderAuthForms()">Login</a></p>
        </div>
    `;
}

async function handleSignup(event) {
    event.preventDefault();
    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;

    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();
        if (response.ok) {
            onAuthSuccess(data.username);
        } else {
            alert(data.message);
        }
    } catch (error) {
        console.error('Signup error:', error);
        alert('Error signing up');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (response.ok) {
            onAuthSuccess(data.username);
        } else {
            alert(data.message);
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Error logging in');
    }
}

function onAuthSuccess(username) {
    authForms.classList.remove('active');
    authForms.classList.add('hidden');
    
    // Update navigation
    authSection.innerHTML = `<span>Welcome, ${username}!</span> <a href="#" onclick="handleLogout()">Logout</a>`;
    
    // Show the project feed by default
    showSection('projects');
}

async function handleLogout() {
    try {
        await fetch('/auth/logout', { method: 'POST' });
        location.reload(); // Refresh the page to reset state
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Placeholder functions for other features
function sendMessage() {
    console.log('Send message functionality to be implemented with Socket.io');
}

function askAI() {
    console.log('AI question functionality to be implemented');
}
