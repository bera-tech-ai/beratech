document.addEventListener('DOMContentLoaded', function() {
    const authBtn = document.getElementById('github-auth-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const reposSection = document.getElementById('repos-section');
    const reposList = document.getElementById('repos-list');
    const modal = document.getElementById('deployment-modal');
    const closeBtn = document.querySelector('.close');
    const logsContainer = document.getElementById('deployment-logs');

    // Check authentication status
    checkAuthStatus();

    // GitHub OAuth
    authBtn.addEventListener('click', () => {
        window.location.href = '/auth/github';
    });

    // Logout
    logoutBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/logout', {
                method: 'POST'
            });
            
            if (response.ok) {
                checkAuthStatus();
            }
        } catch (error) {
            console.error('Logout error:', error);
        }
    });

    // Close modal
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });

    // Check authentication status
    async function checkAuthStatus() {
        try {
            const response = await fetch('/api/user');
            const data = await response.json();
            
            if (data.authenticated) {
                authBtn.style.display = 'none';
                logoutBtn.style.display = 'inline-block';
                reposSection.style.display = 'block';
                loadRepositories();
            } else {
                authBtn.style.display = 'inline-block';
                logoutBtn.style.display = 'none';
                reposSection.style.display = 'none';
            }
        } catch (error) {
            console.error('Auth check error:', error);
        }
    }

    // Load user repositories
    async function loadRepositories() {
        try {
            const response = await fetch('/api/repos');
            const repos = await response.json();
            
            displayRepositories(repos);
        } catch (error) {
            console.error('Error loading repositories:', error);
        }
    }

    // Display repositories
    function displayRepositories(repos) {
        reposList.innerHTML = '';
        
        repos.forEach(repo => {
            const repoCard = document.createElement('div');
            repoCard.className = 'repo-card';
            
            repoCard.innerHTML = `
                <div class="repo-name">${repo.name}</div>
                <div class="repo-description">${repo.description || 'No description'}</div>
                <div class="repo-meta">
                    <span>⭐ ${repo.stargazers_count}</span>
                    <span>${repo.language || 'Unknown'}</span>
                    <span>Updated: ${new Date(repo.updated_at).toLocaleDateString()}</span>
                </div>
                <div class="repo-actions">
                    <button class="btn btn-success deploy-btn" data-owner="${repo.owner.login}" data-repo="${repo.name}">
                        Deploy
                    </button>
                    <button class="btn btn-primary logs-btn" data-owner="${repo.owner.login}" data-repo="${repo.name}">
                        View Logs
                    </button>
                </div>
                <div id="status-${repo.owner.login}-${repo.name}" class="status-container"></div>
            `;
            
            reposList.appendChild(repoCard);
            checkDeploymentStatus(repo.owner.login, repo.name);
        });

        // Add event listeners to buttons
        document.querySelectorAll('.deploy-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const owner = e.target.dataset.owner;
                const repo = e.target.dataset.repo;
                deployRepository(owner, repo);
            });
        });

        document.querySelectorAll('.logs-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const owner = e.target.dataset.owner;
                const repo = e.target.dataset.repo;
                viewLogs(owner, repo);
            });
        });
    }

    // Deploy repository
    async function deployRepository(owner, repo) {
        try {
            logsContainer.innerHTML = 'Starting deployment...';
            modal.style.display = 'block';
            
            const response = await fetch(`/api/deploy/${owner}/${repo}`, {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Poll logs for updates
                pollLogs(owner, repo);
                checkDeploymentStatus(owner, repo);
            } else {
                logsContainer.innerHTML = `Deployment failed: ${data.error}`;
            }
        } catch (error) {
            console.error('Deployment error:', error);
            logsContainer.innerHTML = `Deployment error: ${error.message}`;
        }
    }

    // View deployment logs
    async function viewLogs(owner, repo) {
        try {
            logsContainer.innerHTML = 'Loading logs...';
            modal.style.display = 'block';
            
            const response = await fetch(`/api/logs/${owner}/${repo}`);
            const data = await response.json();
            
            logsContainer.innerHTML = data.logs || 'No logs available';
        } catch (error) {
            console.error('Error loading logs:', error);
            logsContainer.innerHTML = `Error loading logs: ${error.message}`;
        }
    }

    // Poll logs for updates during deployment
    async function pollLogs(owner, repo) {
        const interval = setInterval(async () => {
            try {
                const response = await fetch(`/api/logs/${owner}/${repo}`);
                const data = await response.json();
                
                if (data.logs) {
                    logsContainer.innerHTML = data.logs;
                    logsContainer.scrollTop = logsContainer.scrollHeight;
                }
                
                // Check if deployment is complete
                const statusResponse = await fetch(`/api/status/${owner}/${repo}`);
                const statusData = await statusResponse.json();
                
                if (statusData.running) {
                    clearInterval(interval);
                    checkDeploymentStatus(owner, repo);
                }
            } catch (error) {
                console.error('Error polling logs:', error);
            }
        }, 2000);
    }

    // Check deployment status
    async function checkDeploymentStatus(owner, repo) {
        try {
            const response = await fetch(`/api/status/${owner}/${repo}`);
            const data = await response.json();
            
            const statusElement = document.getElementById(`status-${owner}-${repo}`);
            if (statusElement) {
                let statusClass = 'status-stopped';
                let statusText = 'Not deployed';
                
                if (data.running) {
                    statusClass = 'status-running';
                    statusText = 'Running';
                } else if (data.status === 'created' || data.status === 'restarting') {
                    statusClass = 'status-building';
                    statusText = 'Building';
                }
                
                statusElement.innerHTML = `
                    <span class="status-badge ${statusClass}">${statusText}</span>
                `;
            }
        } catch (error) {
            console.error('Error checking status:', error);
        }
    }
});
