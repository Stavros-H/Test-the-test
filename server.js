const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/speed_smarts',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()')
  .then(() => console.log('Database connected successfully'))
  .catch(err => {
    console.log('Database connection deferred - will retry on first query');
    console.log('If running locally without PostgreSQL, use test-server.js for basic auth testing');
  });

// Session secret (should be in environment variables in production)
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-in-production';

// Helper: Generate session token
const generateSessionToken = () => {
  return require('crypto').randomBytes(32).toString('hex');
};

// Helper: Verify session middleware
const requireAuth = async (req, res, next) => {
  if (!req.cookies.session_token) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE session_token = $1', [req.cookies.session_token]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error('Session verification error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Helper: Check admin role
const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user && req.user.role !== 'teacher') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
};

// Routes

// GET / - Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// GET /register - Serve registration page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// GET /login - Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// GET /dashboard - Protected route
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// GET /admin - Admin-only route
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, role = 'player' } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  
  if (role !== 'player' && role !== 'teacher') {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  try {
    // Check if username or email already exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role',
      [username, email, passwordHash, role]
    );
    
    const user = result.rows[0];
    
    // Create session
    const sessionToken = generateSessionToken();
    await pool.query(
      'UPDATE users SET session_token = $1 WHERE id = $2',
      [sessionToken, user.id]
    );
    
    // Set cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.status(201).json({ user });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Find user by email
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      // Generic error to avoid revealing email existence
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create session
    const sessionToken = generateSessionToken();
    await pool.query(
      'UPDATE users SET session_token = $1 WHERE id = $2',
      [sessionToken, user.id]
    );
    
    // Set cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    // Clear session token
    await pool.query(
      'UPDATE users SET session_token = NULL WHERE id = $1',
      [req.user.id]
    );
    
    // Clear cookie
    res.clearCookie('session_token');
    
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed: ' + err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, email: req.user.email, role: req.user.role } });
});

// Initialize database
const initializeDatabase = async () => {
  try {
    const client = await pool.connect();
    try {
      // Create users table
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(255) UNIQUE NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL DEFAULT 'player' CHECK (role IN ('player', 'teacher')),
          session_token VARCHAR(255),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);
      
      // Create a default admin user for testing (only in development)
      if (process.env.NODE_ENV !== 'production') {
        const adminCheck = await client.query('SELECT * FROM users WHERE email = $1', ['admin@test.com']);
        if (adminCheck.rows.length === 0) {
          const adminHash = await bcrypt.hash('admin123', 10);
          await client.query(
            'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)',
            ['admin', 'admin@test.com', adminHash, 'teacher']
          );
          console.log('Default admin user created: admin/admin123');
        }
      }
      
      console.log('Database initialized successfully');
    } catch (err) {
      console.error('Database initialization error:', err);
    } finally {
      client.release();
    }
  } catch (err) {
    console.log('Database connection failed, will retry on first query');
    console.log('If running locally without PostgreSQL, use test-server.js for basic auth testing');
  }
};

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeDatabase();
});

module.exports = { app, pool };
