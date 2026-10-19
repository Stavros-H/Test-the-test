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
        // NEW APPROACH: Each quiz has its own dedicated question bank
        // This ensures each quiz pulls from its own pool of 12 questions
        console.log('Development mode: setting up dedicated question banks for each quiz...');
        
        try {
          await client.query('BEGIN');
          
          // Clear all quiz-related data (but keep users)
          await client.query('DELETE FROM attempt_answers');
          await client.query('DELETE FROM attempts');
          await client.query('DELETE FROM choices');
          await client.query('DELETE FROM questions');
          await client.query('DELETE FROM quizzes');
          
          // Create 5 quizzes with their own dedicated question banks
          const quizzes = [
            { title: 'World Wander', description: 'Geography, capitals, oceans & landmarks' },
            { title: 'Lab Coats & Launchpads', description: 'Science, space, and nature trivia' },
            { title: 'Back in Time', description: 'World history and famous events' },
            { title: 'Screens & Speakers', description: 'Movies, TV, and music trivia' },
            { title: 'Play Ball & Board', description: 'Sports, games, and everyday trivia' }
          ];
          
          // Each quiz's dedicated question bank (12 questions each)
          const quizQuestionBanks = [
            // Quiz 1: World Wander
            [
              { text: 'What is the capital city of Japan?', choices: [['A', 'Kyoto', false], ['B', 'Osaka', false], ['C', 'Tokyo', true], ['D', 'Nagoya', false]] },
              { text: 'Which is the largest ocean on Earth?', choices: [['A', 'Atlantic', false], ['B', 'Indian', false], ['C', 'Arctic', false], ['D', 'Pacific', true]] },
              { text: 'How many continents are there?', choices: [['A', '5', false], ['B', '6', false], ['C', '7', true], ['D', '8', false]] },
              { text: 'What is the capital of Australia?', choices: [['A', 'Sydney', false], ['B', 'Melbourne', false], ['C', 'Perth', false], ['D', 'Canberra', true]] },
              { text: 'The Amazon Rainforest lies mostly in which country?', choices: [['A', 'Peru', false], ['B', 'Brazil', true], ['C', 'Colombia', false], ['D', 'Venezuela', false]] },
              { text: 'Which river flows through Paris?', choices: [['A', 'Seine', true], ['B', 'Thames', false], ['C', 'Rhine', false], ['D', 'Danube', false]] },
              { text: 'Which country is home to the Great Barrier Reef?', choices: [['A', 'Indonesia', false], ['B', 'Philippines', false], ['C', 'Australia', true], ['D', 'Fiji', false]] },
              { text: 'Which of these countries is in Africa?', choices: [['A', 'Jordan', false], ['B', 'Egypt', true], ['C', 'Nepal', false], ['D', 'Peru', false]] },
              { text: 'What is the largest country in the world by area?', choices: [['A', 'Canada', false], ['B', 'China', false], ['C', 'United States', false], ['D', 'Russia', true]] },
              { text: 'What is the capital of Canada?', choices: [['A', 'Toronto', false], ['B', 'Ottawa', true], ['C', 'Montreal', false], ['D', 'Vancouver', false]] },
              { text: 'The Mariana Trench lies in which ocean?', choices: [['A', 'Atlantic', false], ['B', 'Indian', false], ['C', 'Pacific', true], ['D', 'Southern', false]] },
              { text: 'Mount Everest sits on the border of Nepal and which country?', choices: [['A', 'India', false], ['B', 'China', true], ['C', 'Bhutan', false], ['D', 'Pakistan', false]] }
            ],
            // Quiz 2: Lab Coats & Launchpads
            [
              { text: 'What is the chemical symbol for gold?', choices: [['A', 'Go', false], ['B', 'Au', true], ['C', 'Ag', false], ['D', 'Gd', false]] },
              { text: 'Which planet is known as the Red Planet?', choices: [['A', 'Venus', false], ['B', 'Jupiter', false], ['C', 'Mars', true], ['D', 'Mercury', false]] },
              { text: 'What do plants absorb from the air for photosynthesis?', choices: [['A', 'Oxygen', false], ['B', 'Nitrogen', false], ['C', 'Hydrogen', false], ['D', 'Carbon dioxide', true]] },
              { text: 'How many bones are in the adult human body?', choices: [['A', '186', false], ['B', '196', false], ['C', '206', true], ['D', '216', false]] },
              { text: 'Which is the largest planet in our solar system?', choices: [['A', 'Saturn', false], ['B', 'Jupiter', true], ['C', 'Neptune', false], ['D', 'Earth', false]] },
              { text: 'Which gas makes up most of Earths atmosphere?', choices: [['A', 'Oxygen', false], ['B', 'Carbon dioxide', false], ['C', 'Nitrogen', true], ['D', 'Hydrogen', false]] },
              { text: 'Which of these is NOT a planet?', choices: [['A', 'Europa', true], ['B', 'Venus', false], ['C', 'Mercury', false], ['D', 'Mars', false]] },
              { text: 'What is the approximate speed of light?', choices: [['A', '30,000 km/s', false], ['B', '300,000 km/s', true], ['C', '3,000 km/s', false], ['D', '3,000,000 km/s', false]] },
              { text: 'Which metal is liquid at room temperature?', choices: [['A', 'Mercury', true], ['B', 'Aluminum', false], ['C', 'Lead', false], ['D', 'Zinc', false]] },
              { text: 'What is the chemical formula for table salt?', choices: [['A', 'CO2', false], ['B', 'H2O', false], ['C', 'NaCl', true], ['D', 'O2', false]] },
              { text: 'Which planet is closest to the Sun?', choices: [['A', 'Mercury', true], ['B', 'Venus', false], ['C', 'Mars', false], ['D', 'Jupiter', false]] },
              { text: 'Which dinosaur was a plant-eater?', choices: [['A', 'T. rex', false], ['B', 'Triceratops', true], ['C', 'Velociraptor', false], ['D', 'Allosaurus', false]] }
            ],
            // Quiz 3: Back in Time
            [
              { text: 'Who was the first President of the United States?', choices: [['A', 'Thomas Jefferson', false], ['B', 'John Adams', false], ['C', 'George Washington', true], ['D', 'Benjamin Franklin', false]] },
              { text: 'In which country is the Great Wall located?', choices: [['A', 'Japan', false], ['B', 'India', false], ['C', 'Mongolia', false], ['D', 'China', true]] },
              { text: 'Who painted the Mona Lisa?', choices: [['A', 'Michelangelo', false], ['B', 'Leonardo da Vinci', true], ['C', 'Raphael', false], ['D', 'Donatello', false]] },
              { text: 'In which year did World War II end?', choices: [['A', '1943', false], ['B', '1944', false], ['C', '1945', true], ['D', '1946', false]] },
              { text: 'Which country gave the Statue of Liberty to the US?', choices: [['A', 'Britain', false], ['B', 'France', true], ['C', 'Spain', false], ['D', 'Italy', false]] },
              { text: 'Who was the first person to walk on the Moon?', choices: [['A', 'Buzz Aldrin', false], ['B', 'Yuri Gagarin', false], ['C', 'Neil Armstrong', true], ['D', 'John Glenn', false]] },
              { text: 'Which invention came FIRST?', choices: [['A', 'The telephone', false], ['B', 'The printing press', true], ['C', 'The airplane', false], ['D', 'The television', false]] },
              { text: 'In which year did the Titanic sink?', choices: [['A', '1905', false], ['B', '1912', true], ['C', '1920', false], ['D', '1898', false]] },
              { text: 'Who was the last pharaoh of ancient Egypt?', choices: [['A', 'Nefertiti', false], ['B', 'Cleopatra', true], ['C', 'Hatshepsut', false], ['D', 'Tutankhamun', false]] },
              { text: 'Which ancient city had the Hanging Gardens?', choices: [['A', 'Athens', false], ['B', 'Rome', false], ['C', 'Babylon', true], ['D', 'Alexandria', false]] },
              { text: 'Who was the primary author of the Declaration of Independence?', choices: [['A', 'George Washington', false], ['B', 'Thomas Jefferson', true], ['C', 'Alexander Hamilton', false], ['D', 'John Adams', false]] },
              { text: 'Which empire was ruled by a tsar?', choices: [['A', 'Ottoman', false], ['B', 'Russian', true], ['C', 'Austro-Hungarian', false], ['D', 'Persian', false]] }
            ],
            // Quiz 4: Screens & Speakers
            [
              { text: 'Which movie features a talking snowman named Olaf?', choices: [['A', 'Moana', false], ['B', 'Tangled', false], ['C', 'Frozen', true], ['D', 'Encanto', false]] },
              { text: 'In The Lion King, what is Simbas father name?', choices: [['A', 'Scar', false], ['B', 'Rafiki', false], ['C', 'Zazu', false], ['D', 'Mufasa', true]] },
              { text: 'Who sang Thriller?', choices: [['A', 'Prince', false], ['B', 'Michael Jackson', true], ['C', 'Elvis Presley', false], ['D', 'Bruno Mars', false]] },
              { text: 'Which instrument has 88 keys?', choices: [['A', 'Guitar', false], ['B', 'Violin', false], ['C', 'Piano', true], ['D', 'Harp', false]] },
              { text: 'Who directed Jurassic Park?', choices: [['A', 'Steven Spielberg', true], ['B', 'George Lucas', false], ['C', 'James Cameron', false], ['D', 'Christopher Nolan', false]] },
              { text: 'Which band recorded Hey Jude?', choices: [['A', 'The Rolling Stones', false], ['B', 'The Beach Boys', false], ['C', 'The Beatles', true], ['D', 'Queen', false]] },
              { text: 'Who plays Iron Man in Marvel movies?', choices: [['A', 'Chris Evans', false], ['B', 'Chris Hemsworth', false], ['C', 'Mark Ruffalo', false], ['D', 'Robert Downey Jr.', true]] },
              { text: 'Which movie follows a clownfish searching for his son?', choices: [['A', 'Shark Tale', false], ['B', 'Finding Nemo', true], ['C', 'Lilo & Stitch', false], ['D', 'Shrek', false]] },
              { text: 'Which sitcom features Ross, Rachel, Monica, Chandler, Joey, and Phoebe?', choices: [['A', 'Seinfeld', false], ['B', 'How I Met Your Mother', false], ['C', 'Friends', true], ['D', 'The Big Bang Theory', false]] },
              { text: 'What is Han Solos ship called?', choices: [['A', 'Millennium Falcon', true], ['B', 'Star Destroyer', false], ['C', 'X-wing', false], ['D', 'Enterprise', false]] },
              { text: 'Which film won the first Best Animated Feature Oscar?', choices: [['A', 'Monsters Inc.', false], ['B', 'Shrek', true], ['C', 'Toy Story', false], ['D', 'Spirited Away', false]] },
              { text: 'Who composed The Four Seasons?', choices: [['A', 'Beethoven', false], ['B', 'Mozart', false], ['C', 'Vivaldi', true], ['D', 'Bach', false]] }
            ],
            // Quiz 5: Play Ball & Board
            [
              { text: 'How many players from one soccer team are on the field at once?', choices: [['A', '9', false], ['B', '10', false], ['C', '11', true], ['D', '12', false]] },
              { text: 'What sport is played at Wimbledon?', choices: [['A', 'Golf', false], ['B', 'Cricket', false], ['C', 'Tennis', true], ['D', 'Rugby', false]] },
              { text: 'In Super Mario, what is Marios brother name?', choices: [['A', 'Wario', false], ['B', 'Luigi', true], ['C', 'Yoshi', false], ['D', 'Toad', false]] },
              { text: 'In chess, which piece can ONLY move diagonally?', choices: [['A', 'Rook', false], ['B', 'Knight', false], ['C', 'Bishop', true], ['D', 'Queen', false]] },
              { text: 'How many rings are on the Olympic flag?', choices: [['A', '4', false], ['B', '5', true], ['C', '6', false], ['D', '7', false]] },
              { text: 'Which sport is played with a shuttlecock?', choices: [['A', 'Squash', false], ['B', 'Table tennis', false], ['C', 'Badminton', true], ['D', 'Racquetball', false]] },
              { text: 'In bowling, what is a perfect game score?', choices: [['A', '200', false], ['B', '250', false], ['C', '300', true], ['D', '350', false]] },
              { text: 'Which country hosted the first modern Olympic Games?', choices: [['A', 'Italy', false], ['B', 'Greece', true], ['C', 'France', false], ['D', 'England', false]] },
              { text: 'How many squares are on a standard chessboard?', choices: [['A', '36', false], ['B', '49', false], ['C', '64', true], ['D', '81', false]] },
              { text: 'In which country did golf originate?', choices: [['A', 'United States', false], ['B', 'Scotland', true], ['C', 'England', false], ['D', 'Ireland', false]] },
              { text: 'In bowling, what is three consecutive strikes called?', choices: [['A', 'Hat trick', false], ['B', 'Turkey', true], ['C', 'Triple', false], ['D', 'Triple crown', false]] },
              { text: 'How many minutes is a standard professional soccer match?', choices: [['A', '80', false], ['B', '90', true], ['C', '100', false], ['D', '120', false]] }
            ]
          ];
          
          // Insert each quiz with its dedicated question bank
          for (let i = 0; i < quizzes.length; i++) {
            const quiz = quizzes[i];
            const questions = quizQuestionBanks[i];
            
            // Insert quiz
            const quizResult = await client.query(
              'INSERT INTO quizzes (title, description) VALUES ($1, $2) RETURNING id',
              [quiz.title, quiz.description]
            );
            const quizId = quizResult.rows[0].id;
            
            // Insert each question with its choices
            for (let j = 0; j < questions.length; j++) {
              const q = questions[j];
              
              // Insert question
              const questionResult = await client.query(
                'INSERT INTO questions (quiz_id, text, position) VALUES ($1, $2, $3) RETURNING id',
                [quizId, q.text, j + 1]
              );
              const questionId = questionResult.rows[0].id;
              
              // Insert choices
              for (const [label, text, isCorrect] of q.choices) {
                await client.query(
                  'INSERT INTO choices (question_id, label, text, is_correct) VALUES ($1, $2, $3, $4)',
                  [questionId, label, text, isCorrect]
                );
              }
            }
            
            console.log(`  ✓ ${quiz.title}: 12 questions seeded`);
          }
          
          await client.query('COMMIT');
          console.log('✓ All quizzes set up with dedicated 12-question banks (60 total)');
          
        } catch (err) {
          await client.query('ROLLBACK');
          console.error('Failed to seed quiz data:', err);
          throw err;
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
  
  // 12 questions per quiz (60 total) from the Project Specifications
  const allQuizQuestions = [
    // Quiz 1: World Wander (Geography)
    [
      { text: 'What is the capital city of Japan?', choices: ['Kyoto', 'Osaka', 'Tokyo', 'Nagoya'], correct: 2 },
      { text: 'Which is the largest ocean on Earth?', choices: ['Atlantic', 'Indian', 'Arctic', 'Pacific'], correct: 3 },
      { text: 'How many continents are there?', choices: ['5', '6', '7', '8'], correct: 2 },
      { text: 'What is the capital of Australia?', choices: ['Sydney', 'Melbourne', 'Perth', 'Canberra'], correct: 3 },
      { text: 'The Amazon Rainforest lies mostly in which country?', choices: ['Peru', 'Brazil', 'Colombia', 'Venezuela'], correct: 1 },
      { text: 'Which river flows through Paris?', choices: ['Seine', 'Thames', 'Rhine', 'Danube'], correct: 0 },
      { text: 'Which country is home to the Great Barrier Reef?', choices: ['Indonesia', 'Philippines', 'Australia', 'Fiji'], correct: 2 },
      { text: 'Which of these countries is in Africa?', choices: ['Jordan', 'Egypt', 'Nepal', 'Peru'], correct: 1 },
      { text: 'What is the largest country in the world by area?', choices: ['Canada', 'China', 'United States', 'Russia'], correct: 3 },
      { text: 'What is the capital of Canada?', choices: ['Toronto', 'Ottawa', 'Montreal', 'Vancouver'], correct: 1 },
      { text: 'The Mariana Trench, the deepest place in the ocean, lies in which ocean?', choices: ['Atlantic', 'Indian', 'Pacific', 'Southern'], correct: 2 },
      { text: 'Mount Everest sits on the border of Nepal and which other country?', choices: ['India', 'China', 'Bhutan', 'Pakistan'], correct: 1 }
    ],
    // Quiz 2: Lab Coats & Launchpads (Science & Space)
    [
      { text: 'What is the chemical symbol for gold?', choices: ['Go', 'Au', 'Ag', 'Gd'], correct: 1 },
      { text: 'Which planet is known as the Red Planet?', choices: ['Venus', 'Jupiter', 'Mars', 'Mercury'], correct: 2 },
      { text: 'What do plants absorb from the air to make food (photosynthesis)?', choices: ['Oxygen', 'Nitrogen', 'Hydrogen', 'Carbon dioxide'], correct: 3 },
      { text: 'How many bones are in the adult human body?', choices: ['186', '196', '206', '216'], correct: 2 },
      { text: 'Which is the largest planet in our solar system?', choices: ['Saturn', 'Jupiter', 'Neptune', 'Earth'], correct: 1 },
      { text: 'Which gas makes up most of Earth\'s atmosphere?', choices: ['Oxygen', 'Carbon dioxide', 'Nitrogen', 'Hydrogen'], correct: 2 },
      { text: 'Which of these is NOT a planet?', choices: ['Europa', 'Venus', 'Mercury', 'Mars'], correct: 0 },
      { text: 'What is the approximate speed of light?', choices: ['30,000 km/s', '300,000 km/s', '3,000 km/s', '3,000,000 km/s'], correct: 1 },
      { text: 'Which metal is a liquid at room temperature?', choices: ['Mercury', 'Aluminum', 'Lead', 'Zinc'], correct: 0 },
      { text: 'What is the chemical formula for table salt?', choices: ['CO2', 'H2O', 'NaCl', 'O2'], correct: 2 },
      { text: 'Which planet is closest to the Sun?', choices: ['Mercury', 'Venus', 'Mars', 'Jupiter'], correct: 0 },
      { text: 'Which of these dinosaurs was a plant-eater?', choices: ['T. rex', 'Triceratops', 'Velociraptor', 'Allosaurus'], correct: 1 }
    ],
    // Quiz 3: Back in Time (History)
    [
      { text: 'Who was the first President of the United States?', choices: ['Thomas Jefferson', 'John Adams', 'George Washington', 'Benjamin Franklin'], correct: 2 },
      { text: 'In which country is the Great Wall located?', choices: ['Japan', 'India', 'Mongolia', 'China'], correct: 3 },
      { text: 'Who painted the Mona Lisa?', choices: ['Michelangelo', 'Leonardo da Vinci', 'Raphael', 'Donatello'], correct: 1 },
      { text: 'In which year did World War II end?', choices: ['1943', '1944', '1945', '1946'], correct: 2 },
      { text: 'Which country gave the Statue of Liberty to the United States?', choices: ['Britain', 'France', 'Spain', 'Italy'], correct: 1 },
      { text: 'Who was the first person to walk on the Moon?', choices: ['Buzz Aldrin', 'Yuri Gagarin', 'Neil Armstrong', 'John Glenn'], correct: 2 },
      { text: 'Which of these inventions came FIRST?', choices: ['The telephone', 'The printing press', 'The airplane', 'The television'], correct: 1 },
      { text: 'In which year did the Titanic sink?', choices: ['1905', '1912', '1920', '1898'], correct: 1 },
      { text: 'Who was the famous last pharaoh of ancient Egypt?', choices: ['Nefertiti', 'Cleopatra', 'Hatshepsut', 'Tutankhamun'], correct: 1 },
      { text: 'Which ancient city was famous for its Hanging Gardens?', choices: ['Athens', 'Rome', 'Babylon', 'Alexandria'], correct: 2 },
      { text: 'Who was the primary author of the Declaration of Independence?', choices: ['George Washington', 'Thomas Jefferson', 'Alexander Hamilton', 'John Adams'], correct: 1 },
      { text: 'Which empire was ruled by a leader called a "tsar"?', choices: ['Ottoman', 'Russian', 'Austro-Hungarian', 'Persian'], correct: 1 }
    ],
    // Quiz 4: Screens & Speakers (Movies, TV & Music)
    [
      { text: 'Which movie features a talking snowman named Olaf?', choices: ['Moana', 'Tangled', 'Frozen', 'Encanto'], correct: 2 },
      { text: 'In The Lion King, what is Simba\'s father\'s name?', choices: ['Scar', 'Rafiki', 'Zazu', 'Mufasa'], correct: 3 },
      { text: 'Who sang the hit song \'Thriller\'?', choices: ['Prince', 'Michael Jackson', 'Elvis Presley', 'Bruno Mars'], correct: 1 },
      { text: 'Which musical instrument has 88 keys?', choices: ['Guitar', 'Violin', 'Piano', 'Harp'], correct: 2 },
      { text: 'Who directed Jurassic Park?', choices: ['Steven Spielberg', 'George Lucas', 'James Cameron', 'Christopher Nolan'], correct: 0 },
      { text: 'Which band recorded the song \'Hey Jude\'?', choices: ['The Rolling Stones', 'The Beach Boys', 'The Beatles', 'Queen'], correct: 2 },
      { text: 'In the Marvel movies, who plays Iron Man?', choices: ['Chris Evans', 'Chris Hemsworth', 'Mark Ruffalo', 'Robert Downey Jr.'], correct: 3 },
      { text: 'Which animated movie follows a clownfish searching for his missing son?', choices: ['Shark Tale', 'Finding Nemo', 'Lilo & Stitch', 'Shrek'], correct: 1 },
      { text: 'Which TV sitcom features Ross, Rachel, Monica, Chandler, Joey, and Phoebe?', choices: ['Seinfeld', 'How I Met Your Mother', 'Friends', 'The Big Bang Theory'], correct: 2 },
      { text: 'In Star Wars, what is the name of Han Solo\'s ship?', choices: ['Millennium Falcon', 'Star Destroyer', 'X-wing', 'Enterprise'], correct: 0 },
      { text: 'Which animated film won the very first Academy Award for Best Animated Feature?', choices: ['Monsters, Inc.', 'Shrek', 'Toy Story', 'Spirited Away'], correct: 1 },
      { text: 'Which composer wrote "The Four Seasons"?', choices: ['Beethoven', 'Mozart', 'Vivaldi', 'Bach'], correct: 2 }
    ],
    // Quiz 5: Play Ball & Board (Sports & Games)
    [
      { text: 'How many players from one soccer team are on the field at once?', choices: ['9', '10', '11', '12'], correct: 2 },
      { text: 'What sport is played at Wimbledon?', choices: ['Golf', 'Cricket', 'Tennis', 'Rugby'], correct: 2 },
      { text: 'In the Super Mario video games, what is Mario\'s brother\'s name?', choices: ['Wario', 'Luigi', 'Yoshi', 'Toad'], correct: 1 },
      { text: 'In chess, which piece can ONLY move diagonally?', choices: ['Rook', 'Knight', 'Bishop', 'Queen'], correct: 2 },
      { text: 'How many rings are on the Olympic flag?', choices: ['4', '5', '6', '7'], correct: 1 },
      { text: 'Which sport is played with a shuttlecock?', choices: ['Squash', 'Table tennis', 'Badminton', 'Racquetball'], correct: 2 },
      { text: 'In bowling, what is a perfect game score?', choices: ['200', '250', '300', '350'], correct: 2 },
      { text: 'Which country hosted the first modern Olympic Games?', choices: ['Italy', 'Greece', 'France', 'England'], correct: 1 },
      { text: 'How many squares are on a standard chessboard?', choices: ['36', '49', '64', '81'], correct: 2 },
      { text: 'In which country did the sport of golf originate?', choices: ['United States', 'Scotland', 'England', 'Ireland'], correct: 1 },
      { text: 'In bowling, what is the term for three consecutive strikes?', choices: ['Hat trick', 'Turkey', 'Triple', 'Triple crown'], correct: 1 },
      { text: 'How many minutes long is a standard professional soccer match (before stoppage time)?', choices: ['80', '90', '100', '120'], correct: 1 }
    ]
  ];
  
  for (let i = 0; i < quizTitles.length; i++) {
    const quizResult = await client.query(
      'INSERT INTO quizzes (title, description) VALUES ($1, $2) RETURNING id',
      [quizTitles[i], quizDescriptions[i]]
    );
    const quizId = quizResult.rows[0].id;
    
    // Add all 12 questions for this quiz
    const quizQuestions = allQuizQuestions[i];
    
    for (let j = 0; j < quizQuestions.length; j++) {
      const q = quizQuestions[j];
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
  
  console.log('All quizzes and 12 questions each (60 total) seeded successfully');
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
