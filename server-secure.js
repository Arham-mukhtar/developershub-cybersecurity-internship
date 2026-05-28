// ============================================================
// VULNERABLE VERSION - FOR SECURITY TESTING ONLY
// This app has intentional vulnerabilities for educational use
// DO NOT deploy this in production
// ============================================================

const express = require('express');
const session = require('express-session');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULNERABILITY 1: Weak session secret
app.use(session({
  secret: '123',
  resave: false,
  saveUninitialized: true
}));

// In-memory "database" (simulates SQL injection behavior)
let users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@test.com', role: 'admin' },
  { id: 2, username: 'user1', password: 'password', email: 'user1@test.com', role: 'user' }
];

// ---- ROUTES ----

// Home
app.get('/', (req, res) => {
  res.render('home', { user: req.session.user });
});

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// VULNERABILITY 2: No input validation on signup
// VULNERABILITY 3: Passwords stored in plain text
app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;

  // No validation at all
  const newUser = {
    id: users.length + 1,
    username: username,     // Not sanitized - XSS possible
    email: email,           // Not validated as email
    password: password,     // Plain text - no hashing
    role: 'user'
  };

  users.push(newUser);
  res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// VULNERABILITY 4: SQL injection simulation - no parameterized queries
// VULNERABILITY 5: No rate limiting on login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Simulates what a raw SQL query would do:
  // SELECT * FROM users WHERE username = '<input>' AND password = '<input>'
  // Input: admin' OR '1'='1  => bypasses login
  let user = null;

  if (username.includes("' OR '1'='1")) {
    // Simulate SQL injection success - returns admin
    user = users[0];
  } else {
    user = users.find(u => u.username === username && u.password === password);
  }

  if (user) {
    req.session.user = user;
    res.redirect('/profile');
  } else {
    res.render('login', { error: 'Invalid username or password' });
  }
});

// Profile page
// VULNERABILITY 6: Reflected XSS - user data rendered without escaping
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  // VULNERABILITY 7: Search param reflected directly in page (XSS)
  const search = req.query.search || '';
  res.render('profile', { user: req.session.user, search: search, users: users });
});

// VULNERABILITY 8: No CSRF protection on profile update
app.post('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const { bio } = req.body;
  // bio is stored raw - XSS payload will execute when rendered
  req.session.user.bio = bio;
  res.redirect('/profile');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => {
  console.log('Vulnerable app running at http://localhost:3000');
  console.log('WARNING: This app has intentional vulnerabilities for testing only!');
});
