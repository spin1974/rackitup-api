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

console.log('Allowed CORS origins:', allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS: ' + origin));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Explicitly handle OPTIONS preflight for all routes using same config
app.options('*', cors(corsOptions));

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
      `SELECT user_id, user_password FROM users WHERE user_id = $1 AND deleted_at IS NULL`,
      [req.user.user_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found.' });
    const match = await bcrypt.compare(current_password, result.rows[0].user_password);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      `UPDATE users SET user_password = $1, password_changed_at = NOW(), updated_at = NOW() WHERE user_id = $2`,
      [hash, req.user.user_id]
    );
    res.json({ message: 'Password updated.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SITE ADMIN ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/admin/stats', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL) AS user_count,
        (SELECT COUNT(*) FROM poolhall WHERE poolhall_id > 1) AS poolhall_count,
        (SELECT COUNT(*) FROM player WHERE deleted_at IS NULL) AS player_count,
        (SELECT COUNT(*) FROM chip_tournaments WHERE status = 'finished') AS tournaments_finished,
        (SELECT COUNT(*) FROM chip_tournaments WHERE status IN ('setup', 'running')) AS tournaments_active
    `);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
      JOIN role r ON u.role_id = r.role_id
      JOIN poolhall p ON u.poolhall_id = p.poolhall_id
      ORDER BY u.created_at DESC
    `);
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/users', requireAuth, requireSiteAdmin, async (req, res) => {
  const { user_name, user_password, user_email, poolhall_id, role_id, phone_number, display_name } = req.body;
  if (!user_name || !user_password || !user_email || !role_id) {
    return res.status(400).json({ error: 'user_name, user_password, user_email and role_id are required' });
  }
  try {
    const hash = await bcrypt.hash(user_password, 10);
    const result = await pool.query(
      `INSERT INTO users (user_name, user_password, user_email, poolhall_id, role_id, phone_number, display_name, password_changed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING user_id, user_name, user_email, poolhall_id, role_id, phone_number, display_name, created_at`,
      [user_name, hash, user_email, poolhall_id || 1, role_id, phone_number || null, display_name || null]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/users/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { user_email, poolhall_id, role_id, phone_number, display_name } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET user_email = COALESCE($1, user_email), poolhall_id = COALESCE($2, poolhall_id),
       role_id = COALESCE($3, role_id), phone_number = COALESCE($4, phone_number),
       display_name = COALESCE($5, display_name), updated_at = NOW()
       WHERE user_id = $6
       RETURNING user_id, user_name, user_email, poolhall_id, role_id, phone_number, display_name, updated_at`,
      [user_email, poolhall_id, role_id, phone_number, display_name, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/users/:id/unlock', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE users SET failed_attempts = 0, locked_at = NULL, updated_at = NOW()
       WHERE user_id = $1 RETURNING user_id, user_name`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User unlocked', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/users/:id/password', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { new_password } = req.body;
  if (!new_password || new_password.length < 8) {
    return res.status(400).json({ error: 'new_password must be at least 8 characters.' });
  }
  try {
    const check = await pool.query(`SELECT user_id FROM users WHERE user_id = $1 AND deleted_at IS NULL`, [id]);
    if (!check.rows.length) return res.status(404).json({ error: 'User not found.' });
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      `UPDATE users SET user_password = $1, password_changed_at = NOW(), updated_at = NOW() WHERE user_id = $2`,
      [hash, id]
    );
    res.json({ message: 'Password reset.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/admin/users/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.user_id) return res.status(400).json({ error: 'You cannot delete your own account' });
  try {
    const result = await pool.query(
      `UPDATE users SET deleted_at = NOW(), updated_at = NOW()
       WHERE user_id = $1 AND deleted_at IS NULL RETURNING user_id, user_name`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/users/:id/restore', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE users SET deleted_at = NULL, updated_at = NOW()
       WHERE user_id = $1 AND deleted_at IS NOT NULL RETURNING user_id, user_name`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found or not deleted' });
    res.json({ message: 'User restored', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/poolhalls', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT poolhall_id, poolhall_name, city, province_state, country,
              phone_number, primary_email, website, created_at
       FROM poolhall WHERE poolhall_id > 1 ORDER BY created_at DESC`
    );
    res.json({ poolhalls: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/poolhalls', requireAuth, requireSiteAdmin, async (req, res) => {
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  if (!poolhall_name || !phone_number || !primary_email) {
    return res.status(400).json({ error: 'poolhall_name, phone_number and primary_email are required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO poolhall (poolhall_name, address_line1, address_line2, city, province_state,
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

app.put('/admin/poolhalls/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  try {
    const result = await pool.query(
      `UPDATE poolhall SET poolhall_name = COALESCE($1, poolhall_name),
       address_line1 = COALESCE($2, address_line1), address_line2 = COALESCE($3, address_line2),
       city = COALESCE($4, city), province_state = COALESCE($5, province_state),
       postal_code = COALESCE($6, postal_code), country = COALESCE($7, country),
       phone_number = COALESCE($8, phone_number), primary_email = COALESCE($9, primary_email),
       website = COALESCE($10, website), updated_at = NOW()
       WHERE poolhall_id = $11 RETURNING *`,
      [poolhall_name, address_line1, address_line2, city, province_state,
       postal_code, country, phone_number, primary_email, website, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/poolhalls/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`SELECT * FROM poolhall WHERE poolhall_id = $1`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/poolhalls/:id/users', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT u.user_id, u.user_name, u.user_email, u.role_id, r.role_name,
              u.locked_at, u.deleted_at, u.created_at
       FROM users u JOIN role r ON u.role_id = r.role_id
       WHERE u.poolhall_id = $1 ORDER BY u.created_at ASC`,
      [id]
    );
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/poolhalls/:id/settings', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT setting_name, setting_value, updated_at FROM poolhall_settings
       WHERE poolhall_id = $1 ORDER BY setting_name`, [id]
    );
    const settings = {};
    result.rows.forEach(r => { settings[r.setting_name] = r.setting_value; });
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/poolhalls/:id/settings', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') return res.status(400).json({ error: 'settings object required' });
  try {
    const entries = Object.entries(settings);
    for (const [name, value] of entries) {
      await pool.query(
        `INSERT INTO poolhall_settings (poolhall_id, setting_name, setting_value, updated_at)
         VALUES ($1, $2, $3, NOW()) ON CONFLICT (poolhall_id, setting_name)
         DO UPDATE SET setting_value = $3, updated_at = NOW()`,
        [id, name, value === null || value === undefined ? '' : String(value)]
      );
    }
    res.json({ message: `${entries.length} setting(s) saved` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/db/orphans', requireAuth, requireSiteAdmin, async (req, res) => {
  const minDays = parseInt(req.query.min_age_days, 10);
  if (isNaN(minDays) || minDays < 0) return res.status(400).json({ error: 'min_age_days must be a non-negative integer' });
  try {
    const result = await pool.query(`
      SELECT ct.tournament_id, ct.name, ct.status, ct.created_at,
             ph.poolhall_id, ph.poolhall_name, ph.city, ph.province_state,
             EXTRACT(EPOCH FROM (NOW() - ct.created_at)) / 86400 AS age_days,
             (SELECT COUNT(*) FROM chip_tournament_players ctp WHERE ctp.tournament_id = ct.tournament_id) AS player_count
      FROM chip_tournaments ct JOIN poolhall ph ON ph.poolhall_id = ct.poolhall_id
      WHERE ct.status IN ('setup', 'running')
        AND ct.created_at < NOW() - ($1 || ' days')::INTERVAL
      ORDER BY ct.created_at ASC
    `, [minDays]);
    res.json({ orphans: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/admin/db/tournaments/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(
      `SELECT ct.tournament_id, ct.name, ct.status, ct.created_at, ph.poolhall_name
       FROM chip_tournaments ct JOIN poolhall ph ON ph.poolhall_id = ct.poolhall_id
       WHERE ct.tournament_id = $1`, [id]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const t = check.rows[0];
    await pool.query(`DELETE FROM chip_tournaments WHERE tournament_id = $1`, [id]);
    console.log(`[ADMIN DELETE] tournament_id=${t.tournament_id} name="${t.name}" hall="${t.poolhall_name}" status=${t.status} deleted_by=user_id:${req.user.user_id}`);
    res.json({ deleted: true, tournament_id: t.tournament_id, name: t.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/db/tryleague-orphans ───────────────────────────────────────────
app.get('/admin/db/tryleague-orphans', requireAuth, requireSiteAdmin, async (req, res) => {
  const minDays = parseInt(req.query.min_age_days, 10);
  if (isNaN(minDays) || minDays < 0) return res.status(400).json({ error: 'min_age_days must be a non-negative integer' });
  try {
    const result = await pool.query(`
      SELECT s.session_id, s.name, s.status, s.created_at,
             ph.poolhall_id, ph.poolhall_name, ph.city, ph.province_state,
             EXTRACT(EPOCH FROM (NOW() - s.created_at)) / 86400 AS age_days,
             (SELECT COUNT(*) FROM tryleague_session_players tsp WHERE tsp.session_id = s.session_id) AS player_count
      FROM tryleague_sessions s JOIN poolhall ph ON ph.poolhall_id = s.poolhall_id
      WHERE s.status IN ('setup', 'running')
        AND s.created_at < NOW() - ($1 || ' days')::INTERVAL
      ORDER BY s.created_at ASC
    `, [minDays]);
    res.json({ orphans: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /admin/db/tryleague-sessions/:id ───────────────────────────────────
app.delete('/admin/db/tryleague-sessions/:id', requireAuth, requireSiteAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(
      `SELECT s.session_id, s.name, s.status, s.created_at, ph.poolhall_name
       FROM tryleague_sessions s JOIN poolhall ph ON ph.poolhall_id = s.poolhall_id
       WHERE s.session_id = $1`, [id]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const s = check.rows[0];
    await pool.query(`DELETE FROM tryleague_sessions WHERE session_id = $1`, [id]);
    console.log(`[ADMIN DELETE] tryleague session_id=${s.session_id} name="${s.name}" hall="${s.poolhall_name}" status=${s.status} deleted_by=user_id:${req.user.user_id}`);
    res.json({ deleted: true, session_id: s.session_id, name: s.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HALL ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/hall/profile', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM poolhall WHERE poolhall_id = $1`, [req.hallId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/hall/profile', requireAuth, requireHallAdmin, async (req, res) => {
  const { poolhall_name, address_line1, address_line2, city, province_state,
          postal_code, country, phone_number, primary_email, website } = req.body;
  try {
    const result = await pool.query(
      `UPDATE poolhall SET poolhall_name = COALESCE($1, poolhall_name),
       address_line1 = COALESCE($2, address_line1), address_line2 = COALESCE($3, address_line2),
       city = COALESCE($4, city), province_state = COALESCE($5, province_state),
       postal_code = COALESCE($6, postal_code), country = COALESCE($7, country),
       phone_number = COALESCE($8, phone_number), primary_email = COALESCE($9, primary_email),
       website = COALESCE($10, website), updated_at = NOW()
       WHERE poolhall_id = $11 RETURNING *`,
      [poolhall_name, address_line1, address_line2, city, province_state,
       postal_code, country, phone_number, primary_email, website, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Pool hall not found' });
    res.json({ poolhall: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/hall/settings', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT setting_name, setting_value FROM poolhall_settings WHERE poolhall_id = $1 ORDER BY setting_name`,
      [req.hallId]
    );
    const settings = {};
    result.rows.forEach(r => { settings[r.setting_name] = r.setting_value; });
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/hall/settings', requireAuth, requireHallAdmin, async (req, res) => {
  const { settings } = req.body;
  if (!settings || typeof settings !== 'object') return res.status(400).json({ error: 'settings object required' });
  try {
    const entries = Object.entries(settings);
    for (const [name, value] of entries) {
      await pool.query(
        `INSERT INTO poolhall_settings (poolhall_id, setting_name, setting_value, updated_at)
         VALUES ($1, $2, $3, NOW()) ON CONFLICT (poolhall_id, setting_name)
         DO UPDATE SET setting_value = $3, updated_at = NOW()`,
        [req.hallId, name, value === null || value === undefined ? '' : String(value)]
      );
    }
    res.json({ message: `${entries.length} setting(s) saved` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/hall/stats', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT (SELECT COUNT(*) FROM player WHERE poolhall_id = $1 AND deleted_at IS NULL) AS player_count`,
      [req.hallId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/players ─────────────────────────────────────────────────────────
// Returns players with lifetime try-league stats joined from tryleague_player_stats.
// tl_wins, tl_losses, tl_sessions are 0 when no stats row exists yet.
app.get('/hall/players', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.player_id, p.first_name, p.last_name, p.home_town, p.cell_number,
              p.email_address, p.fargo_id, p.fargo_rating, p.hall_rating, p.tier,
              p.created_at, p.updated_at,
              COALESCE(s.total_wins,     0) AS tl_wins,
              COALESCE(s.total_losses,   0) AS tl_losses,
              COALESCE(s.sessions_played,0) AS tl_sessions
       FROM player p
       LEFT JOIN tryleague_player_stats s
         ON s.player_id = p.player_id AND s.poolhall_id = p.poolhall_id
       WHERE p.poolhall_id = $1 AND p.deleted_at IS NULL
       ORDER BY p.last_name ASC, p.first_name ASC`,
      [req.hallId]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/hall/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { first_name, last_name, home_town, cell_number, email_address,
          fargo_id, fargo_rating, hall_rating, tier } = req.body;
  if (!first_name || !last_name) return res.status(400).json({ error: 'first_name and last_name are required' });
  if (tier && !['A','B','C','D'].includes(tier)) return res.status(400).json({ error: 'tier must be A, B, C, or D' });
  try {
    const result = await pool.query(
      `INSERT INTO player (poolhall_id, first_name, last_name, home_town, cell_number,
        email_address, fargo_id, fargo_rating, hall_rating, tier)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.hallId, first_name, last_name, home_town || null, cell_number || null,
       email_address || null, fargo_id || null, fargo_rating || null, hall_rating || null, tier || null]
    );
    res.status(201).json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/hall/players/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { first_name, last_name, home_town, cell_number, email_address,
          fargo_id, fargo_rating, hall_rating, tier } = req.body;
  if (tier && !['A','B','C','D'].includes(tier)) return res.status(400).json({ error: 'tier must be A, B, C, or D' });
  try {
    const result = await pool.query(
      `UPDATE player SET first_name = COALESCE($1, first_name), last_name = COALESCE($2, last_name),
       home_town = COALESCE($3, home_town), cell_number = COALESCE($4, cell_number),
       email_address = COALESCE($5, email_address), fargo_id = COALESCE($6, fargo_id),
       fargo_rating = COALESCE($7, fargo_rating), hall_rating = COALESCE($8, hall_rating),
       tier = COALESCE($9, tier), updated_at = NOW()
       WHERE player_id = $10 AND poolhall_id = $11 AND deleted_at IS NULL RETURNING *`,
      [first_name, last_name, home_town, cell_number, email_address,
       fargo_id, fargo_rating || null, hall_rating || null, tier, id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
    res.json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/hall/players/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE player SET deleted_at = NOW(), updated_at = NOW()
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

app.get('/hall/tournaments', requireAuth, requireHallAuth, async (req, res) => {
  res.json({ tournaments: [] });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHIP TOURNAMENT ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/hall/chip-tournaments', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status, config, fargo_config,
              created_at, started_at, finished_at
       FROM chip_tournaments WHERE poolhall_id = $1 ORDER BY created_at DESC`,
      [req.hallId]
    );
    res.json({ tournaments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/hall/chip-tournaments', requireAuth, requireHallAdmin, async (req, res) => {
  const { name, config, fargo_config } = req.body;
  if (!config || typeof config !== 'object') return res.status(400).json({ error: 'config object is required' });
  try {
    const result = await pool.query(
      `INSERT INTO chip_tournaments (poolhall_id, name, status, config, fargo_config, created_at)
       VALUES ($1, $2, 'setup', $3, $4, NOW())
       RETURNING tournament_id, poolhall_id, name, status, config, fargo_config, created_at`,
      [req.hallId, name || null, JSON.stringify(config), fargo_config ? JSON.stringify(fargo_config) : null]
    );
    res.status(201).json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, status, config, fargo_config } = req.body;
  const validStatuses = ['setup', 'running', 'finished'];
  if (status && !validStatuses.includes(status)) return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query(
      `SELECT tournament_id, status, started_at, finished_at FROM chip_tournaments
       WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (current.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Tournament not found' }); }
    const row = current.rows[0];
    const isNewFinish = (status === 'finished' && row.status !== 'finished');
    let started_at = row.started_at, finished_at = row.finished_at;
    if (status === 'running' && !started_at) started_at = new Date();
    if (status === 'finished' && !finished_at) finished_at = new Date();
    const result = await client.query(
      `UPDATE chip_tournaments SET name = COALESCE($1, name), status = COALESCE($2, status),
       config = COALESCE($3, config), fargo_config = COALESCE($4, fargo_config),
       started_at = $5, finished_at = $6
       WHERE tournament_id = $7 AND poolhall_id = $8
       RETURNING tournament_id, poolhall_id, name, status, config, fargo_config, created_at, started_at, finished_at`,
      [name || null, status || null, config ? JSON.stringify(config) : null,
       fargo_config ? JSON.stringify(fargo_config) : null, started_at, finished_at, id, req.hallId]
    );
    if (isNewFinish) {
      const players = await client.query(
        `SELECT player_id, wins, losses, rebuys, payout FROM chip_tournament_players
         WHERE tournament_id = $1 AND status IN ('champion', 'eliminated')`, [id]
      );
      for (const p of players.rows) {
        await client.query(
          `INSERT INTO chip_player_stats (player_id, poolhall_id, tournaments_played, total_wins, total_losses, total_rebuys, total_earnings, last_played_at)
           VALUES ($1, $2, 1, $3, $4, $5, $6, NOW())
           ON CONFLICT (player_id, poolhall_id) DO UPDATE SET
             tournaments_played = chip_player_stats.tournaments_played + 1,
             total_wins = chip_player_stats.total_wins + EXCLUDED.total_wins,
             total_losses = chip_player_stats.total_losses + EXCLUDED.total_losses,
             total_rebuys = chip_player_stats.total_rebuys + EXCLUDED.total_rebuys,
             total_earnings = chip_player_stats.total_earnings + EXCLUDED.total_earnings,
             last_played_at = NOW()`,
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

app.delete('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `DELETE FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2
       RETURNING tournament_id, name, status`, [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ message: 'Tournament deleted', tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/hall/chip-tournaments/:id', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status, config, fargo_config, created_at, started_at, finished_at
       FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/hall/chip-tournaments/:id/matches', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(`SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `SELECT match_id, tournament_id, round_seq, table_number, p1_id, p2_id, breaker_id, winner_id, loser_id, status, created_at, finished_at
       FROM chip_matches WHERE tournament_id = $1 ORDER BY match_id ASC`, [id]
    );
    res.json({ matches: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/hall/chip-tournaments/:id/players', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(`SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `SELECT ctp.id, ctp.tournament_id, ctp.player_id, ctp.starting_chips, ctp.current_chips,
              ctp.finish_position, ctp.rebuys, ctp.wins, ctp.losses, ctp.payout, ctp.status, ctp.bye_count,
              p.first_name, p.last_name, p.hall_rating, p.fargo_rating, p.tier
       FROM chip_tournament_players ctp JOIN player p ON ctp.player_id = p.player_id
       WHERE ctp.tournament_id = $1 ORDER BY ctp.id ASC`, [id]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/hall/chip-tournaments/:id/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { player_id, starting_chips, current_chips } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id is required' });
  try {
    const check = await pool.query(`SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const pc = await pool.query(`SELECT player_id FROM player WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL`, [player_id, req.hallId]);
    if (pc.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
    const result = await pool.query(
      `INSERT INTO chip_tournament_players (tournament_id, player_id, starting_chips, current_chips, status)
       VALUES ($1, $2, $3, $4, 'waiting') ON CONFLICT (tournament_id, player_id) DO NOTHING RETURNING *`,
      [id, player_id, starting_chips || null, current_chips || null]
    );
    res.status(201).json({ player: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, playerId } = req.params;
  try {
    const check = await pool.query(`SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `DELETE FROM chip_tournament_players WHERE tournament_id = $1 AND player_id = $2 RETURNING id, player_id`,
      [id, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in tournament' });
    res.json({ message: 'Player removed from tournament', player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, playerId } = req.params;
  const { status, finish_position, current_chips, wins, losses, payout } = req.body;
  try {
    const check = await pool.query(`SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `UPDATE chip_tournament_players SET status = COALESCE($1, status), finish_position = COALESCE($2, finish_position),
       current_chips = COALESCE($3, current_chips), wins = COALESCE($4, wins), losses = COALESCE($5, losses),
       payout = COALESCE($6, payout)
       WHERE tournament_id = $7 AND player_id = $8 RETURNING id, player_id, status, finish_position, payout`,
      [status || null, finish_position || null, current_chips ?? null, wins ?? null, losses ?? null,
       payout != null ? payout : null, id, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in tournament' });
    res.json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/hall/chip-tournaments/:id/matches', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id } = req.body;
  if (!round_seq || !table_number || !p1_player_id || !p2_player_id || !breaker_player_id) {
    return res.status(400).json({ error: 'round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id are required' });
  }
  try {
    const check = await pool.query(`SELECT tournament_id, status FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    if (check.rows[0].status !== 'running') return res.status(409).json({ error: 'Tournament is not running' });
    const result = await pool.query(
      `INSERT INTO chip_matches (tournament_id, round_seq, table_number, p1_id, p2_id, breaker_id, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'playing', NOW()) RETURNING match_id`,
      [id, round_seq, table_number, p1_player_id, p2_player_id, breaker_player_id]
    );
    res.status(201).json({ match_id: result.rows[0].match_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/hall/chip-tournaments/:id/matches/:matchId/result', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, matchId } = req.params;
  const { p1_player_id, p1_chips, p1_wins, p1_losses, p1_status, p2_player_id, p2_chips, p2_wins, p2_losses, p2_status } = req.body;
  if (!p1_player_id || !p2_player_id) return res.status(400).json({ error: 'p1_player_id and p2_player_id are required' });
  try {
    const check = await pool.query(
      `SELECT cm.match_id, cm.status FROM chip_matches cm JOIN chip_tournaments ct ON ct.tournament_id = cm.tournament_id
       WHERE cm.match_id = $1 AND cm.tournament_id = $2 AND ct.poolhall_id = $3`, [matchId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Match not found' });
    if (check.rows[0].status !== 'done') return res.status(409).json({ error: 'Match is not done — nothing to reverse' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE chip_matches SET status = 'playing', winner_id = NULL, loser_id = NULL, finished_at = NULL WHERE match_id = $1`, [matchId]);
      await client.query(`UPDATE chip_tournament_players SET current_chips = $1, wins = $2, losses = $3, status = $4, finish_position = NULL WHERE tournament_id = $5 AND player_id = $6`, [p1_chips, p1_wins, p1_losses, p1_status, id, p1_player_id]);
      await client.query(`UPDATE chip_tournament_players SET current_chips = $1, wins = $2, losses = $3, status = $4, finish_position = NULL WHERE tournament_id = $5 AND player_id = $6`, [p2_chips, p2_wins, p2_losses, p2_status, id, p2_player_id]);
      await client.query('COMMIT');
      res.json({ message: 'Match result reversed' });
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

app.put('/hall/chip-tournaments/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, matchId } = req.params;
  const { winner_player_id, loser_player_id, winner_chips, loser_chips, winner_wins, loser_losses, winner_status, loser_status, loser_finish_position } = req.body;
  if (!winner_player_id || !loser_player_id) return res.status(400).json({ error: 'winner_player_id and loser_player_id are required' });
  try {
    const check = await pool.query(
      `SELECT cm.match_id, cm.status FROM chip_matches cm JOIN chip_tournaments ct ON ct.tournament_id = cm.tournament_id
       WHERE cm.match_id = $1 AND cm.tournament_id = $2 AND ct.poolhall_id = $3`, [matchId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Match not found' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE chip_matches SET status = 'done', winner_id = $1, loser_id = $2, finished_at = NOW() WHERE match_id = $3`, [winner_player_id, loser_player_id, matchId]);
      await client.query(`UPDATE chip_tournament_players SET current_chips = $1, wins = $2, status = $3 WHERE tournament_id = $4 AND player_id = $5`, [winner_chips, winner_wins, winner_status, id, winner_player_id]);
      await client.query(`UPDATE chip_tournament_players SET current_chips = $1, losses = $2, status = $3, finish_position = COALESCE($4, finish_position) WHERE tournament_id = $5 AND player_id = $6`, [loser_chips, loser_losses, loser_status, loser_finish_position || null, id, loser_player_id]);
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

// ═══════════════════════════════════════════════════════════════════════════════
// TRY LEAGUE SESSION ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /hall/tryleague-sessions ──────────────────────────────────────────────
app.get('/hall/tryleague-sessions', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT session_id, poolhall_id, name, status, config, created_at, started_at, finished_at
       FROM tryleague_sessions WHERE poolhall_id = $1 ORDER BY created_at DESC`,
      [req.hallId]
    );
    res.json({ sessions: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/tryleague-sessions ─────────────────────────────────────────────
app.post('/hall/tryleague-sessions', requireAuth, requireHallAdmin, async (req, res) => {
  const { name, config } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO tryleague_sessions (poolhall_id, name, status, config, created_at)
       VALUES ($1, $2, 'setup', $3, NOW())
       RETURNING session_id, poolhall_id, name, status, config, created_at`,
      [req.hallId, name || null, config ? JSON.stringify(config) : JSON.stringify({})]
    );
    res.status(201).json({ session: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/tryleague-sessions/:id ─────────────────────────────────────────
// On 'finished': upserts tryleague_player_stats. Idempotent — re-finishing is a no-op.
app.put('/hall/tryleague-sessions/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, status, config } = req.body;
  const validStatuses = ['setup', 'running', 'finished'];
  if (status && !validStatuses.includes(status)) return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  try {
    const current = await pool.query(
      `SELECT session_id, status, started_at, finished_at, poolhall_id
       FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (current.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const row = current.rows[0];
    const wasAlreadyFinished = row.status === 'finished';
    let started_at = row.started_at, finished_at = row.finished_at;
    if (status === 'running' && !started_at) started_at = new Date();
    if (status === 'finished' && !finished_at) finished_at = new Date();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `UPDATE tryleague_sessions SET name = COALESCE($1, name), status = COALESCE($2, status),
         config = COALESCE($3, config), started_at = $4, finished_at = $5
         WHERE session_id = $6 AND poolhall_id = $7
         RETURNING session_id, poolhall_id, name, status, config, created_at, started_at, finished_at`,
        [name || null, status || null, config ? JSON.stringify(config) : null,
         started_at, finished_at, id, req.hallId]
      );
      if (status === 'finished' && !wasAlreadyFinished) {
        const matches = await client.query(
          `SELECT p1_id, p2_id, winner_id FROM tryleague_matches
           WHERE session_id = $1 AND is_rotate = FALSE AND status = 'done' AND winner_id IS NOT NULL`,
          [id]
        );
        const statsMap = new Map();
        for (const m of matches.rows) {
          const loserId = m.winner_id === m.p1_id ? m.p2_id : m.p1_id;
          const winnerId = m.winner_id;
          if (!statsMap.has(winnerId)) statsMap.set(winnerId, { wins: 0, losses: 0 });
          if (!statsMap.has(loserId))  statsMap.set(loserId,  { wins: 0, losses: 0 });
          statsMap.get(winnerId).wins  += 1;
          statsMap.get(loserId).losses += 1;
        }
        for (const [playerId, delta] of statsMap.entries()) {
          await client.query(
            `INSERT INTO tryleague_player_stats (player_id, poolhall_id, sessions_played, total_wins, total_losses, last_played_at)
             VALUES ($1, $2, 1, $3, $4, NOW())
             ON CONFLICT (player_id, poolhall_id) DO UPDATE SET
               sessions_played = tryleague_player_stats.sessions_played + 1,
               total_wins      = tryleague_player_stats.total_wins      + EXCLUDED.total_wins,
               total_losses    = tryleague_player_stats.total_losses    + EXCLUDED.total_losses,
               last_played_at  = NOW()`,
            [playerId, req.hallId, delta.wins, delta.losses]
          );
        }
        const allRoster = await client.query(`SELECT player_id FROM tryleague_session_players WHERE session_id = $1`, [id]);
        for (const rp of allRoster.rows) {
          if (!statsMap.has(rp.player_id)) {
            await client.query(
              `INSERT INTO tryleague_player_stats (player_id, poolhall_id, sessions_played, total_wins, total_losses, last_played_at)
               VALUES ($1, $2, 1, 0, 0, NOW())
               ON CONFLICT (player_id, poolhall_id) DO UPDATE SET
                 sessions_played = tryleague_player_stats.sessions_played + 1,
                 last_played_at  = NOW()`,
              [rp.player_id, req.hallId]
            );
          }
        }
        console.log(`Session ${id} finished: stats upserted for ${statsMap.size} players, ${allRoster.rows.length} total roster`);
      }
      await client.query('COMMIT');
      res.json({ session: result.rows[0] });
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

// ── DELETE /hall/tryleague-sessions/:id ──────────────────────────────────────
app.delete('/hall/tryleague-sessions/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(
      `SELECT session_id, status FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    // No status restriction — hall_admin can hard-delete any session (cascades to players + matches)
    const result = await pool.query(
      `DELETE FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2 RETURNING session_id, name`,
      [id, req.hallId]
    );
    res.json({ message: 'Session deleted', session: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/tryleague-sessions/:id/players ──────────────────────────────────
app.get('/hall/tryleague-sessions/:id/players', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const result = await pool.query(
      `SELECT lsp.id, lsp.session_id, lsp.player_id, lsp.side, lsp.group_name,
              p.first_name, p.last_name, p.hall_rating, p.fargo_rating, p.tier
       FROM tryleague_session_players lsp JOIN player p ON lsp.player_id = p.player_id
       WHERE lsp.session_id = $1 ORDER BY lsp.id ASC`, [id]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/tryleague-sessions/:id/players ─────────────────────────────────
app.post('/hall/tryleague-sessions/:id/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { player_id } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id is required' });
  try {
    const check = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const pc = await pool.query(`SELECT player_id FROM player WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL`, [player_id, req.hallId]);
    if (pc.rows.length === 0) return res.status(404).json({ error: 'Player not found' });
    const result = await pool.query(
      `INSERT INTO tryleague_session_players (session_id, player_id) VALUES ($1, $2)
       ON CONFLICT (session_id, player_id) DO NOTHING RETURNING id, session_id, player_id`,
      [id, player_id]
    );
    res.status(201).json({ player: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/tryleague-sessions/:id/players/:playerId ─────────────────────
app.delete('/hall/tryleague-sessions/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, playerId } = req.params;
  try {
    const check = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const result = await pool.query(
      `DELETE FROM tryleague_session_players WHERE session_id = $1 AND player_id = $2 RETURNING id, player_id`,
      [id, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in session' });
    res.json({ message: 'Player removed from session', player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/tryleague-sessions/:id/assignments ──────────────────────────────
app.put('/hall/tryleague-sessions/:id/assignments', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const assignments = req.body;
  if (!Array.isArray(assignments) || assignments.length === 0) return res.status(400).json({ error: 'assignments must be a non-empty array' });
  try {
    const check = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const a of assignments) {
        if (!a.player_id) continue;
        await client.query(
          `UPDATE tryleague_session_players SET side = $1, group_name = $2 WHERE session_id = $3 AND player_id = $4`,
          [a.side || null, a.group_name || null, id, a.player_id]
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    res.json({ message: `${assignments.length} assignments written` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/tryleague-sessions/:id/matches ─────────────────────────────────
app.post('/hall/tryleague-sessions/:id/matches', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { matches } = req.body;
  if (!Array.isArray(matches) || matches.length === 0) return res.status(400).json({ error: 'matches must be a non-empty array' });
  try {
    const check = await pool.query(
      `SELECT session_id, status, started_at FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const started_at = check.rows[0].started_at || new Date();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`DELETE FROM tryleague_matches WHERE session_id = $1`, [id]);
      await client.query(`UPDATE tryleague_sessions SET status = 'running', started_at = $1 WHERE session_id = $2`, [started_at, id]);
      const inserted = [];
      for (const m of matches) {
        const result = await client.query(
          `INSERT INTO tryleague_matches (session_id, group_idx, side_id, round_num, is_rotate, p1_id, p2_id, breaker_id, status, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())
           RETURNING match_id, group_idx, side_id, round_num, is_rotate, p1_id, p2_id, breaker_id, status, created_at`,
          [id, m.group_idx, m.side_id, m.round_num, m.is_rotate || false, m.p1_id, m.p2_id, m.breaker_id]
        );
        inserted.push(result.rows[0]);
      }
      await client.query('COMMIT');
      res.status(201).json({ matches: inserted });
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

// ── GET /hall/tryleague-sessions/:id/matches ──────────────────────────────────
app.get('/hall/tryleague-sessions/:id/matches', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const result = await pool.query(
      `SELECT match_id, session_id, group_idx, side_id, round_num, is_rotate, p1_id, p2_id, breaker_id, winner_id,
              score1, score2, status, created_at, finished_at
       FROM tryleague_matches WHERE session_id = $1 ORDER BY match_id ASC`, [id]
    );
    res.json({ matches: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/tryleague-sessions/:id/matches/:matchId ─────────────────────────
app.put('/hall/tryleague-sessions/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, matchId } = req.params;
  const { status, score1, score2, winner_id } = req.body;
  const validStatuses = ['pending', 'playing', 'done'];
  if (status && !validStatuses.includes(status)) return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  try {
    const sc = await pool.query(`SELECT session_id FROM tryleague_sessions WHERE session_id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    if (sc.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    const mc = await pool.query(`SELECT match_id, status FROM tryleague_matches WHERE match_id = $1 AND session_id = $2`, [matchId, id]);
    if (mc.rows.length === 0) return res.status(404).json({ error: 'Match not found' });
    let finished_at_expr;
    if (status === 'done') finished_at_expr = 'NOW()';
    else if (status === 'playing' || status === 'pending') finished_at_expr = 'NULL';
    else finished_at_expr = 'finished_at';
    const result = await pool.query(
      `UPDATE tryleague_matches SET status = COALESCE($1, status), score1 = $2, score2 = $3, winner_id = $4,
       finished_at = ${finished_at_expr}
       WHERE match_id = $5 AND session_id = $6
       RETURNING match_id, session_id, group_idx, side_id, round_num, is_rotate, p1_id, p2_id, breaker_id, winner_id,
                 score1, score2, status, created_at, finished_at`,
      [status || null, score1 ?? null, score2 ?? null, winner_id ?? null, matchId, id]
    );
    res.json({ match: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /public/tryleague-sessions/:id ───────────────────────────────────────
// No auth required — returns session info, roster, and matches for read-only display.
// Only exposes sessions with status 'running' or 'finished' (not 'setup').
app.get('/public/tryleague-sessions/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Session — only running or finished sessions are publicly visible
    const sessionResult = await pool.query(
      `SELECT s.session_id, s.name, s.status, s.config, s.started_at, s.finished_at,
              p.poolhall_name
       FROM tryleague_sessions s
       JOIN poolhall p ON s.poolhall_id = p.poolhall_id
       WHERE s.session_id = $1 AND s.status IN ('running', 'finished')`,
      [id]
    );
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found or not yet started' });
    }
    const session = sessionResult.rows[0];

    // Roster with player details and group/side assignments
    const rosterResult = await pool.query(
      `SELECT lsp.player_id, lsp.side, lsp.group_name,
              p.first_name, p.last_name, p.tier, p.hall_rating
       FROM tryleague_session_players lsp
       JOIN player p ON lsp.player_id = p.player_id
       WHERE lsp.session_id = $1
       ORDER BY lsp.group_name, lsp.side, p.first_name`,
      [id]
    );

    // Matches with player names joined in
    const matchResult = await pool.query(
      `SELECT m.match_id, m.group_idx, m.side_id, m.round_num, m.is_rotate,
              m.status, m.score1, m.score2, m.finished_at,
              m.p1_id, m.p2_id, m.breaker_id, m.winner_id,
              p1.first_name AS p1_first, p1.last_name AS p1_last,
              p2.first_name AS p2_first, p2.last_name AS p2_last,
              pb.first_name AS breaker_first,
              pw.first_name AS winner_first, pw.last_name AS winner_last
       FROM tryleague_matches m
       JOIN player p1 ON m.p1_id = p1.player_id
       JOIN player p2 ON m.p2_id = p2.player_id
       LEFT JOIN player pb ON m.breaker_id = pb.player_id
       LEFT JOIN player pw ON m.winner_id = pw.player_id
       WHERE m.session_id = $1
       ORDER BY m.group_idx, m.round_num, m.match_id`,
      [id]
    );

    res.json({
      session,
      players: rosterResult.rows,
      matches: matchResult.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
