# Speed Smarts - A General Knowledge Quiz App

A web-based quiz application where players take timed general-knowledge quizzes, earn points, track their attempt history, and compete on leaderboards.

## Project Structure

```
speed-smarts/
├── server.js          # Main Express server
├── package.json       # Node.js dependencies
├── .gitignore         # Git ignore rules
├── public/            # Frontend files
│   ├── index.html     # Home page
│   ├── register.html  # Registration page
│   ├── login.html     # Login page
│   ├── dashboard.html # User dashboard
│   ├── admin.html     # Admin panel
│   ├── styles.css     # Global styles
│   ├── auth.js        # Authentication JavaScript
│   └── app.js         # Main application JavaScript
└── README.md          # This file
```

## Features

### Phase 1: Foundation and Authentication ✅
- Express server with static file serving
- PostgreSQL database connection
- User registration with bcrypt password hashing
- Login/logout with HTTP-only session cookies
- Role-based access control (player vs. teacher/admin)
- Basic frontend pages for all auth flows

### Phase 2: Quiz Engine (Next)
- Quiz selection and display
- Question rendering with 4 choices
- Answer submission and scoring
- Results page and retry flow

### Phase 3: Attempts and User History
- Save completed quiz attempts
- Personal attempt history
- Prevent unfinished attempts from counting

### Phase 4: Leaderboards and Admin Tools
- Overall leaderboard (by completed attempts)
- Per-quiz leaderboard (by highest score)
- Admin question editor
- CSV import with validation

### Phase 5: Custom Features
- Stacking Time Bank (Feature A)
- Points System (Feature B)
- Question Shuffle (Bonus)

## Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js 24 LTS, Express 5
- **Database:** PostgreSQL with `pg` library
- **Authentication:** bcrypt (cost 10), HTTP-only cookies
- **Package Manager:** npm

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Stavros-H/Test-the-test.git
   cd Test-the-test
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your database connection string
   ```

4. Start the server:
   ```bash
   npm start
   ```

5. Open your browser to `http://localhost:3000`

## Database Schema

See `server.js` for the current schema. The database is initialized automatically on first run.

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user

## Testing

A default admin user is created in development mode:
- **Email:** admin@test.com
- **Password:** admin123
- **Role:** teacher

## Deployment

The app is designed to run on Replit with PostgreSQL database.

## License

This is a student project for Web Design (AI-assisted development) course.
