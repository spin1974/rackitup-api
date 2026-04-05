require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { Pool } = require('pg');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const LOCKOUT_ATTEMPTS  = 3;       // Failed attempts before lockout
const LOCKOUT_MINUTES   = 30;      // Auto-unlock after this many minutes
const RATE_LIMIT_MAX    = 10;      // Max login attempts per window per IP
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minute window in ms

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS: ' + origin));
    }
  }
}));

app.use(express.json());

// ── Database pool ─────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── In-memory rate limiter (per IP) ──────────────────────────────────────────
// Tracks login attempts per IP address — resets after RATE_LIMIT_WINDOW
const rateLimitStore = new Map();

function checkRateLimit(ip) {
  const now    = Date.now();
  const record = rateLimitStore.get(ip);

  if (!record || now - record.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return true; // allowed
  }

  if (record.count >= RATE_LIMIT_MAX) {
    return false; // blocked
  }

  record.count++;
  return true; // allowed
}

// Clean up old rate limit entries every 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitStore.entries()) {
    if (now - record.windowStart > RATE_LIMIT_WINDOW) {
      rateLimitStore.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW);

// ── Middleware: verify JWT token ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── DB connectivity test ──────────────────────────────────────────────────────
app.get('/db-test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ status: 'connected', time: result.rows[0].time });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ── AUTH: Register new user ───────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { user_name, user_password, user_email, poolhall_id, role_id } = req.body;

  if (!user_name || !user_password || !user_email || !role_id) {
    return res.status(400).json({ error: 'user_name, user_password, user_email and role_id are required' });
  }

  try {
    const hash   = await bcrypt.hash(user_password, 10);
    const result = await pool.query(
      `INSERT INTO users (user_name, user_password, user_email, poolhall_id, role_id)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING user_id, user_name, user_email, poolhall_id, role_id, created_at`,
      [user_name, hash, user_email, poolhall_id || 1, role_id]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Login ───────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const ip       = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const GENERIC  = 'Invalid username or password';

  // Rate limit check
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: GENERIC });
  }

  const { user_name, user_password } = req.body;

  if (!user_name || !user_password) {
    return res.status(400).json({ error: GENERIC });
  }

  try {
    const result = await pool.query(
      `SELECT u.user_id, u.user_name, u.user_email, u.user_password,
              u.poolhall_id, u.role_id, r.role_name,
              u.failed_attempts, u.locked_at
       FROM users u
       JOIN role r ON u.role_id = r.role_id
       WHERE u.user_name = $1`,
      [user_name]
    );

    // User not found — return generic error
    if (result.rows.length === 0) {
      return res.status(401).json({ error: GENERIC });
    }

    const user = result.rows[0];
    const now  = new Date();

    // Check lockout status
    if (user.locked_at) {
      const lockedAt      = new Date(user.locked_at);
      const minutesElapsed = (now - lockedAt) / 1000 / 60;

      if (minutesElapsed < LOCKOUT_MINUTES) {
        // Still locked — return generic error, never reveal lockout
        return res.status(401).json({ error: GENERIC });
      } else {
        // Auto-unlock silently — reset lockout state before proceeding
        await pool.query(
          `UPDATE users SET locked_at = NULL, failed_attempts = 0, updated_at = NOW()
           WHERE user_id = $1`,
          [user.user_id]
        );
        user.locked_at       = null;
        user.failed_attempts = 0;
      }
    }

    // Check password
    const match = await bcrypt.compare(user_password, user.user_password);

    if (!match) {
      const newAttempts = user.failed_attempts + 1;
      if (newAttempts >= LOCKOUT_ATTEMPTS) {
        // Lock the account
        await pool.query(
          `UPDATE users SET failed_attempts = $1, locked_at = NOW(), updated_at = NOW()
           WHERE user_id = $2`,
          [newAttempts, user.user_id]
        );
      } else {
        // Increment counter
        await pool.query(
          `UPDATE users SET failed_attempts = $1, updated_at = NOW()
           WHERE user_id = $2`,
          [newAttempts, user.user_id]
        );
      }
      return res.status(401).json({ error: GENERIC });
    }

    // Successful login — reset failed attempts and issue token
    await pool.query(
      `UPDATE users SET failed_attempts = 0, locked_at = NULL, updated_at = NOW()
       WHERE user_id = $1`,
      [user.user_id]
    );

    const token = jwt.sign(
      {
        user_id:     user.user_id,
        user_name:   user.user_name,
        user_email:  user.user_email,
        poolhall_id: user.poolhall_id,
        role_id:     user.role_id,
        role_name:   user.role_name
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      user: {
        user_id:     user.user_id,
        user_name:   user.user_name,
        user_email:  user.user_email,
        poolhall_id: user.poolhall_id,
        role_id:     user.role_id,
        role_name:   user.role_name
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Verify token / get current user ─────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
