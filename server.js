require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Support multiple allowed origins (comma-separated in env var)
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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Middleware: verify JWT token ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
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
// POST /auth/register
// Body: { user_name, user_password, user_email, poolhall_id, role_id }
app.post('/auth/register', async (req, res) => {
  const { user_name, user_password, user_email, poolhall_id, role_id } = req.body;

  if (!user_name || !user_password || !user_email || !role_id) {
    return res.status(400).json({ error: 'user_name, user_password, user_email and role_id are required' });
  }

  try {
    const hash = await bcrypt.hash(user_password, 10);
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
// POST /auth/login
// Body: { user_name, user_password }
app.post('/auth/login', async (req, res) => {
  const { user_name, user_password } = req.body;

  if (!user_name || !user_password) {
    return res.status(400).json({ error: 'user_name and user_password are required' });
  }

  try {
    const result = await pool.query(
      `SELECT u.user_id, u.user_name, u.user_email, u.user_password,
              u.poolhall_id, u.role_id, r.role_name
       FROM users u
       JOIN role r ON u.role_id = r.role_id
       WHERE u.user_name = $1`,
      [user_name]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(user_password, user.user_password);

    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

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
// GET /auth/me  (requires Authorization: Bearer <token>)
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
