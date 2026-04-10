require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { Pool } = require('pg');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const LOCKOUT_ATTEMPTS  = 3;
const LOCKOUT_MINUTES   = 30;
const RATE_LIMIT_MAX    = 10;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;

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

// ── Rate limiter ──────────────────────────────────────────────────────────────
const rateLimitStore = new Map();

function checkRateLimit(ip) {
  const now    = Date.now();
  const record = rateLimitStore.get(ip);
  if (!record || now - record.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (record.count >= RATE_LIMIT_MAX) return false;
  record.count++;
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitStore.entries()) {
    if (now - record.windowStart > RATE_LIMIT_WINDOW) rateLimitStore.delete(ip);
  }
}, RATE_LIMIT_WINDOW);

// ── Middleware: require valid JWT ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Middleware: require site_admin role ───────────────────────────────────────
function requireSiteAdmin(req, res, next) {
  if (req.user.role_name !== 'site_admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
}

// ── Middleware: require hall_admin or hall_viewer role ────────────────────────
// Injects req.hallId from JWT — all hall routes are automatically scoped.
function requireHallAuth(req, res, next) {
  const role = req.user.role_name;
  if (role !== 'hall_admin' && role !== 'hall_viewer') {
    return res.status(403).json({ error: 'Access denied' });
  }
  req.hallId = req.user.poolhall_id;
  next();
}

// ── Middleware: require hall_admin role (write operations) ────────────────────
function requireHallAdmin(req, res, next) {
  if (req.user.role_name !== 'hall_admin') {
    return res.status(403).json({ error: 'Access denied — hall_admin role required' });
  }
  req.hallId = req.user.poolhall_id;
  next();
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

// ── AUTH: Register ────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { user_name, user_password, user_email, poolhall_id, role_id } = req.body;
  if (!user_name || !user_password || !user_email || !role_id) {
    return res.status(400).json({ error: 'user_name, user_password, user_email and role_id are required' });
  }
  try {
    const hash   = await bcrypt.hash(user_password, 10);
    const result = await pool.query(
      `INSERT INTO users (user_name, user_password, user_email, poolhall_id, role_id, password_changed_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING user_id, user_name, user_email, poolhall_id, role_id, created_at`,
      [user_name, hash, user_email, poolhall_id || 1, role_id]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// ── AUTH: Login ───────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const ip      = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const GENERIC = 'Invalid username or password';

  if (!checkRateLimit(ip)) return res.status(429).json({ error: GENERIC });

  const { user_name, user_password } = req.body;
  if (!user_name || !user_password) return res.status(400).json({ error: GENERIC });

  try {
    const result = await pool.query(
      `SELECT u.user_id, u.user_name, u.user_email, u.user_password,
              u.poolhall_id, u.role_id, r.role_name,
              u.failed_attempts, u.locked_at, u.deleted_at
       FROM users u
       JOIN role r ON u.role_id = r.role_id
       WHERE u.user_name = $1`,
      [user_name]
    );

    if (result.rows.length === 0) return res.status(401).json({ error: GENERIC });

    const user = result.rows[0];
    const now  = new Date();

    if (user.deleted_at) return res.status(401).json({ error: GENERIC });

    if (user.locked_at) {
      const minutesElapsed = (now - new Date(user.locked_at)) / 1000 / 60;
      if (minutesElapsed < LOCKOUT_MINUTES) {
        return res.status(401).json({ error: GENERIC });
      }
      await pool.query(
        `UPDATE users SET locked_at = NULL, failed_attempts = 0, updated_at = NOW() WHERE user_id = $1`,
        [user.user_id]
      );
      user.locked_at = null;
      user.failed_attempts = 0;
    }

    const match = await bcrypt.compare(user_password, user.user_password);
    if (!match) {
      const newAttempts = user.failed_attempts + 1;
      if (newAttempts >= LOCKOUT_ATTEMPTS) {
        await pool.query(
          `UPDATE users SET failed_attempts = $1, locked_at = NOW(), updated_at = NOW() WHERE user_id = $2`,
          [newAttempts, user.user_id]
        );
      } else {
        await pool.query(
          `UPDATE users SET failed_attempts = $1, updated_at = NOW() WHERE user_id = $2`,
          [newAttempts, user.user_id]
        );
      }
      return res.status(401).json({ error: GENERIC });
    }

    await pool.query(
      `UPDATE users SET failed_attempts = 0, locked_at = NULL, last_login_at = NOW(), updated_at = NOW() WHERE user_id = $1`,
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

// ── AUTH: Verify token ────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── AUTH: Change own password ─────────────────────────────────────────────────
// Requires current password — for logged-in users changing their own password.
// Different from /admin/users/:id/password which bypasses current-password check.
app.put('/auth/change-password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'current_password and new_password are required.' });
  }
  if (new_password.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, user_password FROM users
       WHERE user_id = $1 AND deleted_at IS NULL`,
      [req.user.user_id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const match = await bcrypt.compare(current_password, result.rows[0].user_password);
    if (!match) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      `UPDATE users
       SET user_password = $1, password_changed_at = NOW(), updated_at = NOW()
       WHERE user_id = $2`,
      [hash, req.user.user_id]
    );
    res.json({ message: 'Password updated.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SITE ADMIN ENDPOINTS — require auth + site_admin role
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /admin/stats ──────────────────────────────────────────────────────────
app.get('/admin/stats', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users    WHERE deleted_at IS NULL) AS user_count,
        (SELECT COUNT(*) FROM poolhall WHERE poolhall_id > 1)    AS poolhall_count,
        (SELECT COUNT(*) FROM player   WHERE deleted_at IS NULL) AS player_count
    `);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/users ──────────────────────────────────────────────────────────
app.get('/admin/users', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.user_id, u.user_name, u.user_email, u.poolhall_id,
             u.role_id, r.role_name, p.poolhall_name,
             u.phone_number, u.display_name,
             u.failed_attempts, u.locked_at, u.deleted_at,
             u.last_login_at, u.password_changed_at,
             u.created_at, u.updated_at
      FROM users u
      JOIN role     r ON u.role_id     = r.role_id
      JOIN poolhall p ON u.poolhall_id = p.poolhall_id
      ORDER BY u.created_at DESC
    `);
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/users ─────────────────────────────────────────────────────────
app.post('/admin/users', requireAuth, requireSiteAdmin, async (req, res) => {
  const { user_name, user_password, user_email, poolhall_id, role_id,
          phone_number, display_name } = req.body;
  if (!user_name || !user_password || !user_email || !role_id) {
    return res.status(400).json({ error: 'user_name, user_password, user_email and role_id are required' });
  }
  try {
    const hash   = await bcrypt.hash(user_password, 10);
    const result = await pool.query(
      `INSERT INTO users (user_name, user_password, user_email, poolhall_id, role_id,
                          phone_number, display_name, password_changed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING user_id, user_name, user_email, poolhall_id, role_id,
                 phone_number, display_name, created_at`,
      [user_name, hash, user_email, poolhall_id || 1, role_id,
       phone_number || null, display_name || null]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /admin/users/:id ──────────────────────────────────────────────────────
app.put('/admin/users/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { user_email, poolhall_id, role_id, phone_number, display_name } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users
       SET user_email    = COALESCE($1, user_email),
           poolhall_id   = COALESCE($2, poolhall_id),
           role_id       = COALESCE($3, role_id),
           phone_number  = COALESCE($4, phone_number),
           display_name  = COALESCE($5, display_name),
           updated_at    = NOW()
       WHERE user_id = $6
       RETURNING user_id, user_name, user_email, poolhall_id, role_id,
                 phone_number, display_name, updated_at`,
      [user_email, poolhall_id, role_id, phone_number, display_name, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /admin/users/:id/unlock ───────────────────────────────────────────────
app.put('/admin/users/:id/unlock', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE users
       SET failed_attempts = 0, locked_at = NULL, updated_at = NOW()
       WHERE user_id = $1
       RETURNING user_id, user_name`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User unlocked', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/users/:id (soft delete) ─────────────────────────────────────
app.delete('/admin/users/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.user_id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }
  try {
    const result = await pool.query(
      `UPDATE users SET deleted_at = NOW(), updated_at = NOW()
       WHERE user_id = $1 AND deleted_at IS NULL
       RETURNING user_id, user_name`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/poolhalls ──────────────────────────────────────────────────────
app.get('/admin/poolhalls', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT poolhall_id, poolhall_name, city, province_state, country,
             phone_number, primary_email, website, created_at
      FROM poolhall
      WHERE poolhall_id > 1
      ORDER BY created_at DESC
    `);
    res.json({ poolhalls: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /admin/poolhalls ─────────────────────────────────────────────────────
app.post('/admin/poolhalls', requireAuth, requireSiteAdmin, async (req, res) => {
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  if (!poolhall_name || !phone_number || !primary_email) {
    return res.status(400).json({ error: 'poolhall_name, phone_number and primary_email are required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO poolhall
         (poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website, public_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, LEFT(MD5(RANDOM()::TEXT), 12))
       RETURNING *`,
      [poolhall_name, address_line1, address_line2, city, province_state,
       postal_code, country || 'Canada', phone_number, primary_email, website]
    );
    res.status(201).json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /admin/poolhalls/:id ──────────────────────────────────────────────────
app.put('/admin/poolhalls/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  try {
    const result = await pool.query(
      `UPDATE poolhall
       SET poolhall_name  = COALESCE($1,  poolhall_name),
           address_line1  = COALESCE($2,  address_line1),
           address_line2  = COALESCE($3,  address_line2),
           city           = COALESCE($4,  city),
           province_state = COALESCE($5,  province_state),
           postal_code    = COALESCE($6,  postal_code),
           country        = COALESCE($7,  country),
           phone_number   = COALESCE($8,  phone_number),
           primary_email  = COALESCE($9,  primary_email),
           website        = COALESCE($10, website),
           updated_at     = NOW()
       WHERE poolhall_id = $11
       RETURNING *`,
      [poolhall_name, address_line1, address_line2, city, province_state,
       postal_code, country, phone_number, primary_email, website, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/poolhalls/:id ──────────────────────────────────────────────────
app.get('/admin/poolhalls/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM poolhall WHERE poolhall_id = $1`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/poolhalls/:id/users ────────────────────────────────────────────
app.get('/admin/poolhalls/:id/users', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT u.user_id, u.user_name, u.user_email,
              u.role_id, r.role_name,
              u.locked_at, u.deleted_at, u.created_at
       FROM users u
       JOIN role r ON u.role_id = r.role_id
       WHERE u.poolhall_id = $1
       ORDER BY u.created_at ASC`,
      [id]
    );
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/poolhalls/:id/settings ─────────────────────────────────────────
app.get('/admin/poolhalls/:id/settings', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT setting_name, setting_value, updated_at
       FROM poolhall_settings
       WHERE poolhall_id = $1
       ORDER BY setting_name`,
      [id]
    );
    // Return as flat key→value object for convenience
    const settings = {};
    result.rows.forEach(r => { settings[r.setting_name] = r.setting_value; });
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /admin/poolhalls/:id/settings ─────────────────────────────────────────
// Body: { settings: { key: value, ... } }
app.put('/admin/poolhalls/:id/settings', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'settings object required' });
  }
  try {
    const entries = Object.entries(settings);
    for (const [name, value] of entries) {
      await pool.query(
        `INSERT INTO poolhall_settings (poolhall_id, setting_name, setting_value, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (poolhall_id, setting_name)
         DO UPDATE SET setting_value = $3, updated_at = NOW()`,
        [id, name, value === null || value === undefined ? '' : String(value)]
      );
    }
    res.json({ message: `${entries.length} setting(s) saved` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HALL ADMIN ENDPOINTS — require auth + hall_admin or hall_viewer role
// All routes are automatically scoped to req.hallId from JWT
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /hall/profile ─────────────────────────────────────────────────────────
app.get('/hall/profile', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM poolhall WHERE poolhall_id = $1`,
      [req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/profile ─────────────────────────────────────────────────────────
app.put('/hall/profile', requireAuth, requireHallAdmin, async (req, res) => {
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  try {
    const result = await pool.query(
      `UPDATE poolhall
       SET poolhall_name  = COALESCE($1,  poolhall_name),
           address_line1  = COALESCE($2,  address_line1),
           address_line2  = COALESCE($3,  address_line2),
           city           = COALESCE($4,  city),
           province_state = COALESCE($5,  province_state),
           postal_code    = COALESCE($6,  postal_code),
           country        = COALESCE($7,  country),
           phone_number   = COALESCE($8,  phone_number),
           primary_email  = COALESCE($9,  primary_email),
           website        = COALESCE($10, website),
           updated_at     = NOW()
       WHERE poolhall_id = $11
       RETURNING *`,
      [poolhall_name, address_line1, address_line2, city, province_state,
       postal_code, country, phone_number, primary_email, website, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/settings ────────────────────────────────────────────────────────
app.get('/hall/settings', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT setting_name, setting_value
       FROM poolhall_settings
       WHERE poolhall_id = $1
       ORDER BY setting_name`,
      [req.hallId]
    );
    const settings = {};
    result.rows.forEach(r => { settings[r.setting_name] = r.setting_value; });
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/settings ────────────────────────────────────────────────────────
// Body: { settings: { key: value, ... } }
app.put('/hall/settings', requireAuth, requireHallAdmin, async (req, res) => {
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'settings object required' });
  }
  try {
    const entries = Object.entries(settings);
    for (const [name, value] of entries) {
      await pool.query(
        `INSERT INTO poolhall_settings (poolhall_id, setting_name, setting_value, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (poolhall_id, setting_name)
         DO UPDATE SET setting_value = $3, updated_at = NOW()`,
        [req.hallId, name, value === null || value === undefined ? '' : String(value)]
      );
    }
    res.json({ message: `${entries.length} setting(s) saved` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/stats ───────────────────────────────────────────────────────────
app.get('/hall/stats', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM player WHERE poolhall_id = $1 AND deleted_at IS NULL) AS player_count
    `, [req.hallId]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/players ─────────────────────────────────────────────────────────
app.get('/hall/players', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT player_id, first_name, last_name, home_town, cell_number,
              email_address, fargo_id, fargo_rating, hall_rating, tier,
              created_at, updated_at
       FROM player
       WHERE poolhall_id = $1 AND deleted_at IS NULL
       ORDER BY last_name ASC, first_name ASC`,
      [req.hallId]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/players ────────────────────────────────────────────────────────
app.post('/hall/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { first_name, last_name, home_town, cell_number, email_address,
          fargo_id, fargo_rating, hall_rating, tier } = req.body;
  if (!first_name || !last_name) {
    return res.status(400).json({ error: 'first_name and last_name are required' });
  }
  if (tier && !['A','B','C','D'].includes(tier)) {
    return res.status(400).json({ error: 'tier must be A, B, C, or D' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO player
         (poolhall_id, first_name, last_name, home_town, cell_number,
          email_address, fargo_id, fargo_rating, hall_rating, tier)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING *`,
      [req.hallId, first_name, last_name,
       home_town || null, cell_number || null, email_address || null,
       fargo_id || null,
       fargo_rating || null, hall_rating || null,
       tier || null]
    );
    res.status(201).json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/players/:id ─────────────────────────────────────────────────────
app.put('/hall/players/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { first_name, last_name, home_town, cell_number, email_address,
          fargo_id, fargo_rating, hall_rating, tier } = req.body;
  if (tier && !['A','B','C','D'].includes(tier)) {
    return res.status(400).json({ error: 'tier must be A, B, C, or D' });
  }
  try {
    // Scope check: ensure player belongs to this hall
    const result = await pool.query(
      `UPDATE player
       SET first_name    = COALESCE($1,  first_name),
           last_name     = COALESCE($2,  last_name),
           home_town     = COALESCE($3,  home_town),
           cell_number   = COALESCE($4,  cell_number),
           email_address = COALESCE($5,  email_address),
           fargo_id      = COALESCE($6,  fargo_id),
           fargo_rating  = COALESCE($7,  fargo_rating),
           hall_rating   = COALESCE($8,  hall_rating),
           tier          = COALESCE($9,  tier),
           updated_at    = NOW()
       WHERE player_id = $10 AND poolhall_id = $11 AND deleted_at IS NULL
       RETURNING *`,
      [first_name, last_name, home_town, cell_number, email_address,
       fargo_id, fargo_rating || null, hall_rating || null, tier,
       id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
    res.json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/players/:id (soft delete) ────────────────────────────────────
app.delete('/hall/players/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE player
       SET deleted_at = NOW(), updated_at = NOW()
       WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL
       RETURNING player_id, first_name, last_name`,
      [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
    res.json({ message: 'Player deleted', player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/tournaments ─────────────────────────────────────────────────────
// Stub — returns empty list until tournament persistence is built
app.get('/hall/tournaments', requireAuth, requireHallAuth, async (req, res) => {
  res.json({ tournaments: [] });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHIP TOURNAMENT ENDPOINTS — require auth + hall role
// All routes automatically scoped to req.hallId from JWT
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /hall/chip-tournaments ────────────────────────────────────────────────
// Returns all tournaments for this hall (all statuses), newest first
app.get('/hall/chip-tournaments', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status,
              config, fargo_config,
              created_at, started_at, finished_at
       FROM chip_tournaments
       WHERE poolhall_id = $1
       ORDER BY created_at DESC`,
      [req.hallId]
    );
    res.json({ tournaments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/chip-tournaments ───────────────────────────────────────────────
// Body: { name, config, fargo_config }
// name is optional — defaults to date + sequence if omitted (applied client-side)
// config and fargo_config are full JSONB objects
app.post('/hall/chip-tournaments', requireAuth, requireHallAdmin, async (req, res) => {
  const { name, config, fargo_config } = req.body;
  if (!config || typeof config !== 'object') {
    return res.status(400).json({ error: 'config object is required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO chip_tournaments
         (poolhall_id, name, status, config, fargo_config, created_at)
       VALUES ($1, $2, 'setup', $3, $4, NOW())
       RETURNING tournament_id, poolhall_id, name, status,
                 config, fargo_config, created_at`,
      [req.hallId,
       name || null,
       JSON.stringify(config),
       fargo_config ? JSON.stringify(fargo_config) : null]
    );
    res.status(201).json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/chip-tournaments/:id ────────────────────────────────────────────
// Updates name, status, config, fargo_config, and lifecycle timestamps.
// Sets started_at when status transitions to 'running' (if not already set).
// Sets finished_at when status transitions to 'finished' (if not already set).
// On first transition to 'finished': upserts chip_player_stats for every
// player in the tournament (tournaments_played, wins, losses, rebuys,
// earnings, last_played_at) scoped to this pool hall.
app.put('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, status, config, fargo_config } = req.body;

  const validStatuses = ['setup', 'running', 'finished'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Fetch current row — scoped to this hall
    const current = await client.query(
      `SELECT tournament_id, status, started_at, finished_at
       FROM chip_tournaments
       WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (current.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Tournament not found' });
    }

    const row = current.rows[0];
    const isNewFinish = (status === 'finished' && row.status !== 'finished');

    // Resolve lifecycle timestamps
    let started_at  = row.started_at;
    let finished_at = row.finished_at;

    if (status === 'running'  && !started_at)  started_at  = new Date();
    if (status === 'finished' && !finished_at) finished_at = new Date();

    const result = await client.query(
      `UPDATE chip_tournaments
       SET name         = COALESCE($1, name),
           status       = COALESCE($2, status),
           config       = COALESCE($3, config),
           fargo_config = COALESCE($4, fargo_config),
           started_at   = $5,
           finished_at  = $6
       WHERE tournament_id = $7 AND poolhall_id = $8
       RETURNING tournament_id, poolhall_id, name, status,
                 config, fargo_config, created_at, started_at, finished_at`,
      [name || null,
       status || null,
       config       ? JSON.stringify(config)       : null,
       fargo_config ? JSON.stringify(fargo_config) : null,
       started_at,
       finished_at,
       id,
       req.hallId]
    );

    // On first finish transition: upsert lifetime stats for every participant
    if (isNewFinish) {
      const players = await client.query(
        `SELECT player_id, wins, losses, rebuys, payout
         FROM chip_tournament_players
         WHERE tournament_id = $1`,
        [id]
      );

      for (const p of players.rows) {
        await client.query(
          `INSERT INTO chip_player_stats
             (player_id, poolhall_id, tournaments_played, total_wins, total_losses,
              total_rebuys, total_earnings, last_played_at)
           VALUES ($1, $2, 1, $3, $4, $5, $6, NOW())
           ON CONFLICT (player_id, poolhall_id) DO UPDATE
             SET tournaments_played = chip_player_stats.tournaments_played + 1,
                 total_wins         = chip_player_stats.total_wins   + EXCLUDED.total_wins,
                 total_losses       = chip_player_stats.total_losses + EXCLUDED.total_losses,
                 total_rebuys       = chip_player_stats.total_rebuys + EXCLUDED.total_rebuys,
                 total_earnings     = chip_player_stats.total_earnings + EXCLUDED.total_earnings,
                 last_played_at     = NOW()`,
          [p.player_id, req.hallId, p.wins, p.losses, p.rebuys, p.payout || 0]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ tournament: result.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ── DELETE /hall/chip-tournaments/:id ─────────────────────────────────────────
// Hard delete — CASCADE removes all roster rows (chip_tournament_players)
// Only permitted when status is 'setup' (not mid-tournament)
app.delete('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `DELETE FROM chip_tournaments
       WHERE tournament_id = $1 AND poolhall_id = $2
       RETURNING tournament_id, name, status`,
      [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ message: 'Tournament deleted', tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/chip-tournaments/:id/players ────────────────────────────────────
app.get('/hall/chip-tournaments/:id/players', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    // Scope check: tournament must belong to this hall
    const check = await pool.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    const result = await pool.query(
      `SELECT ctp.id, ctp.tournament_id, ctp.player_id,
              ctp.starting_chips, ctp.current_chips, ctp.finish_position,
              ctp.rebuys, ctp.wins, ctp.losses, ctp.payout, ctp.status, ctp.bye_count,
              p.first_name, p.last_name, p.hall_rating, p.fargo_rating, p.tier
       FROM chip_tournament_players ctp
       JOIN player p ON ctp.player_id = p.player_id
       WHERE ctp.tournament_id = $1
       ORDER BY ctp.id ASC`,
      [id]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/chip-tournaments/:id/players ───────────────────────────────────
// Body: { player_id, starting_chips, current_chips }
app.post('/hall/chip-tournaments/:id/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { player_id, starting_chips, current_chips } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id is required' });
  try {
    // Scope check: tournament must belong to this hall
    const check = await pool.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    // Scope check: player must belong to this hall
    const playerCheck = await pool.query(
      `SELECT player_id FROM player WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL`,
      [player_id, req.hallId]
    );
    if (playerCheck.rows.length === 0) return res.status(404).json({ error: 'Player not found' });

    const result = await pool.query(
      `INSERT INTO chip_tournament_players
         (tournament_id, player_id, starting_chips, current_chips, status)
       VALUES ($1, $2, $3, $4, 'waiting')
       ON CONFLICT (tournament_id, player_id) DO NOTHING
       RETURNING *`,
      [id, player_id, starting_chips || null, current_chips || null]
    );
    res.status(201).json({ player: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/chip-tournaments/:id/players/:playerId ───────────────────────
app.delete('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, playerId } = req.params;
  try {
    // Scope check: tournament must belong to this hall
    const check = await pool.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    const result = await pool.query(
      `DELETE FROM chip_tournament_players
       WHERE tournament_id = $1 AND player_id = $2
       RETURNING id, player_id`,
      [id, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in tournament' });
    res.json({ message: 'Player removed from tournament', player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/chip-tournaments/:id/players/:playerId ──────────────────────────
// Updates a single player's row in chip_tournament_players.
// Used to mark the champion (status='champion', finish_position=1) at tournament
// end, and to write each player's payout and final stats on completion.
// Body: { status, finish_position, current_chips, wins, losses, payout } — all optional
app.put('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, playerId } = req.params;
  const { status, finish_position, current_chips, wins, losses, payout } = req.body;

  try {
    const check = await pool.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    const result = await pool.query(
      `UPDATE chip_tournament_players
       SET status          = COALESCE($1, status),
           finish_position = COALESCE($2, finish_position),
           current_chips   = COALESCE($3, current_chips),
           wins            = COALESCE($4, wins),
           losses          = COALESCE($5, losses),
           payout          = COALESCE($6, payout)
       WHERE tournament_id = $7 AND player_id = $8
       RETURNING id, player_id, status, finish_position, payout`,
      [status || null, finish_position || null, current_chips ?? null, wins ?? null, losses ?? null,
       payout != null ? payout : null,
       id, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in tournament' });
    res.json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/chip-tournaments/:id/matches ───────────────────────────────────
// Creates a single match row. Called by drawNextMatches() for each pairing.
// Body: { round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id }
// Returns the new match_id (DB PK) so the frontend can store it for later PUT.
app.post('/hall/chip-tournaments/:id/matches', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id } = req.body;

  if (!round_seq || !table_number || !p1_player_id || !p2_player_id || !breaker_player_id) {
    return res.status(400).json({ error: 'round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id are required' });
  }

  try {
    // Scope check: tournament must belong to this hall and be running
    const check = await pool.query(
      `SELECT tournament_id, status FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    if (check.rows[0].status !== 'running') return res.status(409).json({ error: 'Tournament is not running' });

    const result = await pool.query(
      `INSERT INTO chip_matches
         (tournament_id, round_seq, table_number, p1_id, p2_id, breaker_id, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'playing', NOW())
       RETURNING match_id`,
      [id, round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id]
    );

    res.status(201).json({ match_id: result.rows[0].match_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/chip-tournaments/:id/matches/:matchId ───────────────────────────
// Records a match result. Updates chip_matches and both players' rows in
// chip_tournament_players in a single transaction.
// Body: { winner_player_id, loser_player_id, winner_chips, loser_chips,
//         winner_wins, loser_losses, winner_status, loser_status,
//         loser_finish_position (optional, set when eliminated) }
app.put('/hall/chip-tournaments/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, matchId } = req.params;
  const {
    winner_player_id,
    loser_player_id,
    winner_chips,
    loser_chips,
    winner_wins,
    loser_losses,
    winner_status,
    loser_status,
    loser_finish_position
  } = req.body;

  if (!winner_player_id || !loser_player_id) {
    return res.status(400).json({ error: 'winner_player_id and loser_player_id are required' });
  }

  try {
    // Scope check
    const check = await pool.query(
      `SELECT cm.match_id, cm.status
       FROM chip_matches cm
       JOIN chip_tournaments ct ON ct.tournament_id = cm.tournament_id
       WHERE cm.match_id = $1 AND cm.tournament_id = $2 AND ct.poolhall_id = $3`,
      [matchId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Match not found' });
    if (check.rows[0].status === 'done') return res.status(409).json({ error: 'Match already recorded' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Update the match row
      await client.query(
        `UPDATE chip_matches
         SET status      = 'done',
             winner_id   = $1,
             loser_id    = $2,
             finished_at = NOW()
         WHERE match_id = $3`,
        [winner_player_id, loser_player_id, matchId]
      );

      // Update winner's player row
      await client.query(
        `UPDATE chip_tournament_players
         SET current_chips = $1,
             wins          = $2,
             status        = $3
         WHERE tournament_id = $4 AND player_id = $5`,
        [winner_chips, winner_wins, winner_status, id, winner_player_id]
      );

      // Update loser's player row (include finish_position if eliminated)
      await client.query(
        `UPDATE chip_tournament_players
         SET current_chips   = $1,
             losses          = $2,
             status          = $3,
             finish_position = COALESCE($4, finish_position)
         WHERE tournament_id = $5 AND player_id = $6`,
        [loser_chips, loser_losses, loser_status,
         loser_finish_position || null,
         id, loser_player_id]
      );

      await client.query('COMMIT');
      res.json({ message: 'Match result recorded' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
