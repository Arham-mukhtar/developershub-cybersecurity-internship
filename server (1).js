// ============================================================
// SECURED VERSION - All vulnerabilities from Week 1 are fixed
// Week 2 & 3 security implementation
// ============================================================

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();

// ---- LOGGING SETUP (Week 3) ----
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Application starting up...');

// ---- SECURITY HEADERS (Week 2 - Helmet.js) ----
// FIX: Adds X-Frame-Options, X-XSS-Protection, Content-Security-Policy, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    }
  }
}));

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// FIX: Strong session secret + secure settings
app.use(session({
  secret: process.env.SESSION_SECRET || 'a-very-long-random-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,       // Prevents JS access to cookies
    secure: false,        // Set to true in production with HTTPS
    maxAge: 1000 * 60 * 60  // 1 hour
  }
}));

// ---- RATE LIMITING (Week 3 - prevents brute force) ----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 login attempts per 15 min per IP
  message: 'Too many login attempts. Please wait 15 minutes.',
  handler: (req, res) => {
    logger.warn(`Rate limit hit on /login from IP: ${req.ip}`);
    res.status(429).render('login', { error: 'Too many attempts. Try again in 15 minutes.' });
  }
});

// In-memory user store (replace with a real DB in production)
let users = [];

// Seed one admin user with hashed password
(async () => {
  const hashed = await bcrypt.hash('Admin@123', 10);
  users.push({ id: 1, username: 'admin', password: hashed, email: 'admin@test.com', role: 'admin', bio: '' });
  logger.info('Admin user seeded');
})();

// ---- INPUT SANITIZATION helper ----
function sanitizeText(input) {
  // Escape HTML to prevent XSS
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ---- ROUTES ----

app.get('/', (req, res) => {
  res.render('home', { user: req.session.user });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// FIX: Validation + sanitization + password hashing
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // FIX: Input validation using validator library
    if (!username || username.trim().length < 3) {
      return res.render('signup', { error: 'Username must be at least 3 characters.' });
    }

    // FIX: Alphanumeric usernames only - blocks injection characters
    if (!validator.isAlphanumeric(username)) {
      return res.render('signup', { error: 'Username must contain only letters and numbers.' });
    }

    if (!validator.isEmail(email)) {
      return res.render('signup', { error: 'Please provide a valid email address.' });
    }

    // FIX: Strong password requirements
    if (!validator.isStrongPassword(password, { minLength: 8, minNumbers: 1, minSymbols: 1 })) {
      return res.render('signup', { error: 'Password must be 8+ chars with a number and symbol.' });
    }

    // Check if username already taken
    if (users.find(u => u.username === username)) {
      return res.render('signup', { error: 'Username already taken.' });
    }

    // FIX: Hash password with bcrypt (10 salt rounds)
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length + 1,
      username: sanitizeText(username),
      email: sanitizeText(email),
      password: hashedPassword,     // Stored hashed - never plain text
      role: 'user',
      bio: ''
    };

    users.push(newUser);
    logger.info(`New user registered: ${username}`);
    res.redirect('/login');

  } catch (err) {
    logger.error(`Signup error: ${err.message}`);
    res.status(500).render('signup', { error: 'Something went wrong. Try again.' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// FIX: Rate-limited login + bcrypt comparison + JWT token
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.render('login', { error: 'Please fill in all fields.' });
    }

    // FIX: Find user by username only, then compare password separately
    // This eliminates SQL injection risk entirely
    const user = users.find(u => u.username === username);

    if (!user) {
      // FIX: Generic error - don't reveal if username exists
      logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
      return res.render('login', { error: 'Invalid username or password.' });
    }

    // FIX: bcrypt comparison - timing-safe
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      logger.warn(`Wrong password for user: ${username} from IP: ${req.ip}`);
      return res.render('login', { error: 'Invalid username or password.' });
    }

    // FIX: JWT token generation
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'change-this-secret-in-production',
      { expiresIn: '1h' }
    );

    // Store sanitized user in session (no password)
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      bio: user.bio
    };
    req.session.token = token;

    logger.info(`Successful login: ${username} from IP: ${req.ip}`);
    res.redirect('/profile');

  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).render('login', { error: 'Something went wrong. Try again.' });
  }
});

// FIX: Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    logger.warn(`Unauthenticated access attempt to ${req.path} from IP: ${req.ip}`);
    return res.redirect('/login');
  }
  next();
}

// FIX: Search param sanitized before rendering
app.get('/profile', requireAuth, (req, res) => {
  const rawSearch = req.query.search || '';
  const safeSearch = sanitizeText(rawSearch); // FIX: sanitize URL params
  res.render('profile', { user: req.session.user, search: safeSearch });
});

// FIX: Bio is sanitized before storing
app.post('/profile', requireAuth, (req, res) => {
  const { bio } = req.body;
  const safeBio = sanitizeText(bio || '');

  // Update in session and users array
  req.session.user.bio = safeBio;
  const u = users.find(u => u.id === req.session.user.id);
  if (u) u.bio = safeBio;

  logger.info(`Profile updated for user: ${req.session.user.username}`);
  res.redirect('/profile');
});

app.get('/logout', (req, res) => {
  const username = req.session.user ? req.session.user.username : 'unknown';
  logger.info(`User logged out: ${username}`);
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => {
  logger.info('Secure app running at http://localhost:3000');
});
