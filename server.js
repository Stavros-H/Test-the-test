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
const rejectUnauthenticatedRequest = (req, res, message) => {
  res.clearCookie('session_token');

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: message });
  }

  return res.redirect('/login');
};

const requireAuth = async (req, res, next) => {
  if (!req.cookies.session_token) {
    return rejectUnauthenticatedRequest(req, res, 'Not logged in');
  }
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE session_token = $1', [req.cookies.session_token]);
    if (result.rows.length === 0) {
      return rejectUnauthenticatedRequest(req, res, 'Invalid session');
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

// GET /quizzes - List all quizzes
app.get('/quizzes', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quizzes.html'));
});

// GET /quizzes/:id - Play a specific quiz
app.get('/quizzes/:id', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quiz.html'));
});

// GET /quizzes/:id/results - Show quiz results
app.get('/quizzes/:id/results', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'results.html'));
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

// ============ QUIZ API ROUTES ============

// GET /api/quizzes - List all quizzes with question counts
app.get('/api/quizzes', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT q.id, q.title, q.description, 
             COUNT(DISTINCT qn.id) as question_count
      FROM quizzes q
      LEFT JOIN questions qn ON q.id = qn.quiz_id AND qn.deleted_at IS NULL
      GROUP BY q.id, q.title, q.description
      ORDER BY q.id
    `);
    
    const quizzes = result.rows.map(q => ({
      id: q.id,
      title: q.title,
      description: q.description,
      question_count: parseInt(q.question_count)
    }));
    
    res.json({ quizzes });
  } catch (err) {
    console.error('Error fetching quizzes:', err);
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});

// GET /api/quizzes/:id - Get quiz details with questions and choices (no correct answers)
app.get('/api/quizzes/:id', requireAuth, async (req, res) => {
  try {
    const quizId = parseInt(req.params.id);
    
    // Get quiz info
    const quizResult = await pool.query(
      'SELECT id, title, description FROM quizzes WHERE id = $1',
      [quizId]
    );
    
    if (quizResult.rows.length === 0) {
      return res.status(404).json({ error: 'Quiz not found' });
    }
    
    const quiz = quizResult.rows[0];
    
    // Get active questions with choices (shuffled per attempt - will be handled in start attempt)
    const questionsResult = await pool.query(`
      SELECT q.id as question_id, q.text as question_text, q.position,
             c.id as choice_id, c.label, c.text as choice_text
      FROM questions q
      JOIN choices c ON q.id = c.question_id
      WHERE q.quiz_id = $1 AND q.deleted_at IS NULL
      ORDER BY q.position, c.label
    `, [quizId]);
    
    // Group choices by question
    const questionsMap = new Map();
    questionsResult.rows.forEach(row => {
      if (!questionsMap.has(row.question_id)) {
        questionsMap.set(row.question_id, {
          id: row.question_id,
          text: row.question_text,
          position: row.position,
          choices: []
        });
      }
      questionsMap.get(row.question_id).choices.push({
        id: row.choice_id,
        label: row.label,
        text: row.choice_text
      });
    });
    
    const questions = Array.from(questionsMap.values());
    
    res.json({ quiz, questions });
  } catch (err) {
    console.error('Error fetching quiz:', err);
    res.status(500).json({ error: 'Failed to fetch quiz' });
  }
});

// POST /api/quizzes/:id/attempts - Start a new quiz attempt
app.post('/api/quizzes/:id/attempts', requireAuth, async (req, res) => {
  try {
    const quizId = parseInt(req.params.id);
    const userId = req.user.id;
    
    // Verify quiz exists
    const quizResult = await pool.query(
      'SELECT id FROM quizzes WHERE id = $1',
      [quizId]
    );
    
    if (quizResult.rows.length === 0) {
      return res.status(404).json({ error: 'Quiz not found' });
    }
    
    // Get active questions for this quiz
    const questionsResult = await pool.query(`
      SELECT id FROM questions 
      WHERE quiz_id = $1 AND deleted_at IS NULL
      ORDER BY random() -- Shuffle questions
    `, [quizId]);
    
    if (questionsResult.rows.length === 0) {
      return res.status(400).json({ error: 'Quiz has no questions' });
    }
    
    const questionIds = questionsResult.rows.map(r => r.id);
    const questionCount = questionIds.length;
    
    // Create attempt with initial time bank of 15 seconds
    const attemptResult = await pool.query(`
      INSERT INTO attempts 
      (user_id, quiz_id, score, question_count, points, time_bank, timed_out, started_at)
      VALUES ($1, $2, 0, $3, 0, 15, false, NOW())
      RETURNING id
    `, [userId, quizId, questionCount]);
    
    const attemptId = attemptResult.rows[0].id;
    
    // Shuffle choices for each question and store the order
    const shuffledQuestions = [];
    for (const qId of questionIds) {
      const choicesResult = await pool.query(`
        SELECT id, label, text FROM choices 
        WHERE question_id = $1
        ORDER BY random()
      `, [qId]);
      
      shuffledQuestions.push({
        question_id: qId,
        choices: choicesResult.rows
      });
    }
    
    res.json({
      attempt_id: attemptId,
      quiz_id: quizId,
      question_count: questionCount,
      questions: shuffledQuestions,
      time_bank: 15,
      reading_buffer: 3
    });
  } catch (err) {
    console.error('Error starting attempt:', err);
    res.status(500).json({ error: 'Failed to start attempt: ' + err.message });
  }
});

// POST /api/attempts/:id/answers - Submit answer for a question
app.post('/api/attempts/:id/answers', requireAuth, async (req, res) => {
  try {
    const attemptId = parseInt(req.params.id);
    const { question_id, choice_id, seconds_remaining } = req.body;
    
    // Get attempt info
    const attemptResult = await pool.query(
      'SELECT * FROM attempts WHERE id = $1 AND user_id = $2',
      [attemptId, req.user.id]
    );
    
    if (attemptResult.rows.length === 0) {
      return res.status(404).json({ error: 'Attempt not found or not yours' });
    }
    
    const attempt = attemptResult.rows[0];
    
    // Check if this attempt is already completed
    if (attempt.completed_at) {
      return res.status(400).json({ error: 'Attempt already completed' });
    }
    
    // Get question and correct choice
    const questionResult = await pool.query(
      'SELECT * FROM questions WHERE id = $1',
      [question_id]
    );
    
    if (questionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Question not found' });
    }
    
    const correctChoiceResult = await pool.query(
      'SELECT id FROM choices WHERE question_id = $1 AND is_correct = true',
      [question_id]
    );
    
    const correctChoiceId = correctChoiceResult.rows[0]?.id;
    const isCorrect = choice_id === correctChoiceId;
    
    // Calculate points based on the Stacking Time Bank rules
    let pointsEarned = 0;
    let newTimeBank = attempt.time_bank;
    
    // B = seconds_remaining (whole seconds left when answer lands)
    const B = Math.floor(seconds_remaining);
    
    if (isCorrect) {
      // Correct: 100 + 10 * B
      pointsEarned = 100 + (10 * B);
      
      // Bank update: B + floor(B / 2) if B < 40; no add if B >= 40; cap at 60
      if (B < 40) {
        newTimeBank = Math.min(60, attempt.time_bank + B + Math.floor(B / 2));
      }
      // If B >= 40, no addition to bank
    } else {
      // Wrong: 50 + 5 * B (half credit)
      pointsEarned = 50 + (5 * B);
      
      // Bank update: B - 5, with 3-second mercy floor
      newTimeBank = Math.max(3, B - 5);
    }
    
    // Update attempt with new score, points, and time bank
    const updatedAttempt = await pool.query(`
      UPDATE attempts 
      SET score = score + $1, 
          points = points + $2, 
          time_bank = $3
      WHERE id = $4
      RETURNING *
    `, [isCorrect ? 1 : 0, pointsEarned, newTimeBank, attemptId]);
    
    // Record the answer
    await pool.query(`
      INSERT INTO attempt_answers 
      (attempt_id, question_id, choice_id, is_correct, seconds_remaining, answered_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [attemptId, question_id, choice_id, isCorrect, B]);
    
    // Check if this was the last question
    const answersCount = await pool.query(
      'SELECT COUNT(*) FROM attempt_answers WHERE attempt_id = $1',
      [attemptId]
    );
    
    const isLastQuestion = parseInt(answersCount.rows[0].count) >= attempt.question_count;
    
    res.json({
      correct: isCorrect,
      points: pointsEarned,
      new_time_bank: newTimeBank,
      next_reading_buffer: 3,
      is_last_question: isLastQuestion
    });
  } catch (err) {
    console.error('Error submitting answer:', err);
    res.status(500).json({ error: 'Failed to submit answer: ' + err.message });
  }
});

// POST /api/attempts/:id/complete - Complete a quiz attempt
app.post('/api/attempts/:id/complete', requireAuth, async (req, res) => {
  try {
    const attemptId = parseInt(req.params.id);
    
    // Get attempt info
    const attemptResult = await pool.query(
      'SELECT * FROM attempts WHERE id = $1 AND user_id = $2',
      [attemptId, req.user.id]
    );
    
    if (attemptResult.rows.length === 0) {
      return res.status(404).json({ error: 'Attempt not found or not yours' });
    }
    
    const attempt = attemptResult.rows[0];
    
    // Check if already completed
    if (attempt.completed_at) {
      return res.status(400).json({ error: 'Attempt already completed' });
    }
    
    // Mark as completed
    const updatedAttempt = await pool.query(`
      UPDATE attempts 
      SET completed_at = NOW()
      WHERE id = $1
      RETURNING *
    `, [attemptId]);
    
    const completedAttempt = updatedAttempt.rows[0];
    
    // Calculate percentage
    const percentage = Math.round((completedAttempt.score / completedAttempt.question_count) * 100);
    
    res.json({
      score: completedAttempt.score,
      question_count: completedAttempt.question_count,
      percentage: percentage,
      points: completedAttempt.points,
      completed: true
    });
  } catch (err) {
    console.error('Error completing attempt:', err);
    res.status(500).json({ error: 'Failed to complete attempt: ' + err.message });
  }
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
      
      // Create quizzes table
      await client.query(`
        CREATE TABLE IF NOT EXISTS quizzes (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);
      
      // Create questions table
      await client.query(`
        CREATE TABLE IF NOT EXISTS questions (
          id SERIAL PRIMARY KEY,
          quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
          text TEXT NOT NULL,
          position INTEGER NOT NULL DEFAULT 0,
          deleted_at TIMESTAMP WITH TIME ZONE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);
      
      // Create choices table
      await client.query(`
        CREATE TABLE IF NOT EXISTS choices (
          id SERIAL PRIMARY KEY,
          question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
          label VARCHAR(10) NOT NULL CHECK (label IN ('A', 'B', 'C', 'D')),
          text TEXT NOT NULL,
          is_correct BOOLEAN NOT NULL DEFAULT false
        )
      `);
      
      // Create attempts table
      await client.query(`
        CREATE TABLE IF NOT EXISTS attempts (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
          score INTEGER NOT NULL DEFAULT 0,
          question_count INTEGER NOT NULL DEFAULT 0,
          points INTEGER NOT NULL DEFAULT 0,
          time_bank INTEGER NOT NULL DEFAULT 15,
          timed_out BOOLEAN NOT NULL DEFAULT false,
          started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          completed_at TIMESTAMP WITH TIME ZONE
        )
      `);
      
      // Create attempt_answers table
      await client.query(`
        CREATE TABLE IF NOT EXISTS attempt_answers (
          id SERIAL PRIMARY KEY,
          attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
          question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
          choice_id INTEGER REFERENCES choices(id) ON DELETE SET NULL,
          is_correct BOOLEAN NOT NULL DEFAULT false,
          seconds_remaining INTEGER NOT NULL DEFAULT 0,
          answered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);
      
      // Seed initial quizzes and questions for testing (only in development)
      if (process.env.NODE_ENV !== 'production') {
        const quizCheck = await client.query('SELECT COUNT(*) FROM quizzes');
        if (parseInt(quizCheck.rows[0].count) === 0) {
          await seedTestData(client);
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

// Helper: Seed test data
const seedTestData = async (client) => {
  // Insert 5 quizzes
  const quizTitles = [
    'World Wander',
    'Lab Coats & Launchpads', 
    'Back in Time',
    'Screens & Speakers',
    'Play Ball & Board'
  ];
  
  const quizDescriptions = [
    'Geography, capitals, oceans & landmarks',
    'Science, space, and nature trivia',
    'World history and famous events',
    'Movies, TV, and music trivia',
    'Sports, games, and everyday trivia'
  ];
  
  for (let i = 0; i < quizTitles.length; i++) {
    const quizResult = await client.query(
      'INSERT INTO quizzes (title, description) VALUES ($1, $2) RETURNING id',
      [quizTitles[i], quizDescriptions[i]]
    );
    const quizId = quizResult.rows[0].id;
    
    // Add sample questions for each quiz
    const sampleQuestions = [
      { text: 'What is the capital of France?', choices: ['Paris', 'London', 'Berlin', 'Madrid'], correct: 0 },
      { text: 'Which planet is known as the Red Planet?', choices: ['Venus', 'Jupiter', 'Mars', 'Mercury'], correct: 2 },
      { text: 'Who painted the Mona Lisa?', choices: ['Michelangelo', 'Leonardo da Vinci', 'Raphael', 'Donatello'], correct: 1 }
    ];
    
    for (let j = 0; j < sampleQuestions.length; j++) {
      const q = sampleQuestions[j];
      const questionResult = await client.query(
        'INSERT INTO questions (quiz_id, text, position) VALUES ($1, $2, $3) RETURNING id',
        [quizId, q.text, j + 1]
      );
      const questionId = questionResult.rows[0].id;
      
      for (let k = 0; k < q.choices.length; k++) {
        const label = ['A', 'B', 'C', 'D'][k];
        await client.query(
          'INSERT INTO choices (question_id, label, text, is_correct) VALUES ($1, $2, $3, $4)',
          [questionId, label, q.choices[k], k === q.correct]
        );
      }
    }
  }
  
  console.log('Sample quizzes and questions seeded for testing');
};

// Initialize database first, then start server
const startServer = async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  }
};

startServer();

module.exports = { app, pool };
