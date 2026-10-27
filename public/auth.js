// Authentication handling

// Register form handler
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const role = document.querySelector('input[name="role"]:checked').value;
            const errorMessage = document.getElementById('errorMessage');
            const successMessage = document.getElementById('successMessage');
            
            // Validate
            if (password !== confirmPassword) {
                showError(errorMessage, 'Passwords do not match');
                return;
            }
            
            if (password.length < 6) {
                showError(errorMessage, 'Password must be at least 6 characters');
                return;
            }
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password, role })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    showError(errorMessage, data.error || 'Registration failed');
                    return;
                }
                
                // Success - redirect to dashboard
                showSuccess(successMessage, 'Registration successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1500);
            } catch (err) {
                console.error('Registration error:', err);
                showError(errorMessage, 'Registration failed. Please try again.');
            }
        });
    }
    
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('errorMessage');
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    showError(errorMessage, data.error || 'Login failed');
                    return;
                }
                
                // Success - redirect to dashboard
                window.location.href = '/dashboard';
            } catch (err) {
                console.error('Login error:', err);
                showError(errorMessage, 'Login failed. Please try again.');
            }
        });
    }
});

// Helper functions
function showError(element, message) {
    element.textContent = message;
    element.classList.add('show');
    
    // Hide success message if visible
    const successMessage = document.getElementById('successMessage');
    if (successMessage) {
        successMessage.classList.remove('show');
    }
}

function showSuccess(element, message) {
    element.textContent = message;
    element.classList.add('show');
    
    // Hide error message if visible
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.classList.remove('show');
    }
}

// Generic fetch helper for auth-protected routes
async function authFetch(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        credentials: 'include'
    });
    
    if (response.status === 401) {
        // Session expired, redirect to login
        window.location.href = '/login';
        return null;
    }
    
    return response;
}

// Quiz-specific helpers
function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
}
