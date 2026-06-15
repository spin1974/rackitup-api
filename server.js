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

// ── GET /admin/roles ──────────────────────────────────────────────────────────
// Returns all assignable roles for user management dropdowns.
// team_captain is excluded — captain accounts are created via QR onboarding (Phase 4),
// not manually by admins.
app.get('/admin/roles', requireAuth, requireSiteAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT role_id, role_name FROM role
       WHERE role_name != 'team_captain'
       ORDER BY role_id ASC`
    );
    res.json({ roles: result.rows });
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
// ROUND ROBIN TOURNAMENT ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /hall/roundrobin-tournaments ─────────────────────────────────────────
app.get('/hall/roundrobin-tournaments', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.tournament_id, t.name, t.status, t.config, t.created_at, t.updated_at,
              COUNT(rtp.tournament_player_id)::int AS player_count
       FROM roundrobin_tournaments t
       LEFT JOIN roundrobin_tournament_players rtp ON rtp.tournament_id = t.tournament_id
       WHERE t.poolhall_id = $1
       GROUP BY t.tournament_id
       ORDER BY t.created_at DESC`,
      [req.hallId]
    );
    res.json({ tournaments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/roundrobin-tournaments ────────────────────────────────────────
app.post('/hall/roundrobin-tournaments', requireAuth, requireHallAdmin, async (req, res) => {
  const { name, config } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Tournament name is required' });
  try {
    // Guard: only one active tournament at a time
    const active = await pool.query(
      `SELECT tournament_id FROM roundrobin_tournaments
       WHERE poolhall_id = $1 AND status IN ('setup', 'running') LIMIT 1`,
      [req.hallId]
    );
    if (active.rows.length > 0) {
      return res.status(409).json({ error: 'A tournament is already active. Finish it before creating a new one.' });
    }
    const result = await pool.query(
      `INSERT INTO roundrobin_tournaments (poolhall_id, name, status, config, created_at, updated_at)
       VALUES ($1, $2, 'setup', $3, NOW(), NOW())
       RETURNING tournament_id, poolhall_id, name, status, config, created_at, updated_at`,
      [req.hallId, name.trim(), config ? JSON.stringify(config) : JSON.stringify({})]
    );
    res.status(201).json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/roundrobin-tournaments/:id ─────────────────────────────────────
app.get('/hall/roundrobin-tournaments/:id', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const tResult = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status, config, created_at, updated_at
       FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (tResult.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    const pResult = await pool.query(
      `SELECT rtp.tournament_player_id, rtp.player_id, rtp.group_idx, rtp.seed_rating, rtp.created_at,
              p.first_name, p.last_name, p.hall_rating, p.fargo_rating, p.tier
       FROM roundrobin_tournament_players rtp
       JOIN player p ON p.player_id = rtp.player_id
       WHERE rtp.tournament_id = $1
       ORDER BY rtp.seed_rating DESC NULLS LAST, p.last_name`,
      [id]
    );

    res.json({ tournament: tResult.rows[0], players: pResult.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/roundrobin-tournaments/:id ─────────────────────────────────────
app.put('/hall/roundrobin-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, status, config } = req.body;
  const validStatuses = ['setup', 'running', 'finished'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  }
  try {
    const result = await pool.query(
      `UPDATE roundrobin_tournaments
       SET name       = COALESCE($1, name),
           status     = COALESCE($2, status),
           config     = COALESCE($3, config),
           updated_at = NOW()
       WHERE tournament_id = $4 AND poolhall_id = $5
       RETURNING tournament_id, poolhall_id, name, status, config, created_at, updated_at`,
      [name || null, status || null, config ? JSON.stringify(config) : null, id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/roundrobin-tournaments/:id ───────────────────────────────────
app.delete('/hall/roundrobin-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `DELETE FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2
       RETURNING tournament_id, name`,
      [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ message: 'Tournament deleted', tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/roundrobin-tournaments/:id/players ─────────────────────────────
app.post('/hall/roundrobin-tournaments/:id/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { player_id } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id is required' });
  try {
    const tCheck = await pool.query(
      `SELECT tournament_id, status FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (tCheck.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    if (tCheck.rows[0].status === 'finished') return res.status(409).json({ error: 'Cannot add players to a finished tournament' });

    const pCheck = await pool.query(
      `SELECT player_id, hall_rating FROM player WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL`,
      [player_id, req.hallId]
    );
    if (pCheck.rows.length === 0) return res.status(404).json({ error: 'Player not found' });

    const seedRating = pCheck.rows[0].hall_rating || null;
    const result = await pool.query(
      `INSERT INTO roundrobin_tournament_players (tournament_id, player_id, seed_rating, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (tournament_id, player_id) DO NOTHING
       RETURNING tournament_player_id, tournament_id, player_id, group_idx, seed_rating, created_at`,
      [id, player_id, seedRating]
    );
    if (!result.rows.length) return res.status(409).json({ error: 'Player already registered' });
    res.status(201).json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/roundrobin-tournaments/:id/players/:pid ─────────────────────
app.delete('/hall/roundrobin-tournaments/:id/players/:pid', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, pid } = req.params;
  try {
    const tCheck = await pool.query(
      `SELECT tournament_id FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (tCheck.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `DELETE FROM roundrobin_tournament_players WHERE tournament_id = $1 AND player_id = $2
       RETURNING tournament_player_id, player_id`,
      [id, pid]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not in tournament' });
    res.json({ message: 'Player removed', player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/roundrobin-tournaments/:id/schedule ────────────────────────────
// Generates groups + full match schedule. Deletes any existing matches first.
// Transitions tournament status → 'running'.
// Body: {
//   groups: 1|2|3,
//   group_assignments: [{ player_id, group_idx }],
//   group_config: [{ group_idx, rounds, matches_per_opponent }]  ← optional, per-group overrides
// }
//   group_assignments is the admin-confirmed list after drag adjustment.
//   If omitted, players are auto-split by seed_rating descending.
//   group_config overrides the tournament-level rounds/matches_per_opponent per group.
//   Falls back to tournament config values if group_config is omitted or incomplete.
app.post('/hall/roundrobin-tournaments/:id/schedule', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { groups: numGroups = 1, group_assignments, group_config } = req.body;

  if (![1, 2, 3].includes(Number(numGroups))) {
    return res.status(400).json({ error: 'groups must be 1, 2, or 3' });
  }

  try {
    const tResult = await pool.query(
      `SELECT tournament_id, poolhall_id, status, config
       FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (tResult.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    if (tResult.rows[0].status === 'finished') return res.status(409).json({ error: 'Tournament is already finished' });

    const cfg = tResult.rows[0].config || {};
    const defaultRounds = Number(cfg.rounds)              || 5;
    const defaultMpo    = Number(cfg.matches_per_opponent) || 3;

    // Build per-group config map: group_idx → { rounds, matchesPerRound }
    // Seeded from group_config body param; falls back to tournament config defaults
    const groupCfgMap = new Map();
    if (Array.isArray(group_config)) {
      for (const gc of group_config) {
        groupCfgMap.set(Number(gc.group_idx), {
          rounds:          Number(gc.rounds)               || defaultRounds,
          matchesPerRound: Number(gc.matches_per_opponent) || defaultMpo
        });
      }
    }

    // Load registered players ordered by seed_rating desc
    const pResult = await pool.query(
      `SELECT rtp.player_id, rtp.seed_rating
       FROM roundrobin_tournament_players rtp
       WHERE rtp.tournament_id = $1
       ORDER BY rtp.seed_rating DESC NULLS LAST`,
      [id]
    );
    const allPlayers = pResult.rows;
    if (allPlayers.length < 2) {
      return res.status(400).json({ error: 'Need at least 2 players to generate a schedule' });
    }

    const N = Number(numGroups);

    // ── Assign players to groups ──────────────────────────────────────────────
    // Use provided assignments if supplied, otherwise auto-split by rating order
    let groupMap = new Map(); // group_idx (0-based) → [player_id, ...]
    for (let g = 0; g < N; g++) groupMap.set(g, []);

    if (group_assignments && group_assignments.length) {
      for (const a of group_assignments) {
        const gi = Number(a.group_idx);
        if (gi >= 0 && gi < N) groupMap.get(gi).push(Number(a.player_id));
      }
      // Any registered player missing from assignments falls into group 0
      const assigned = new Set(group_assignments.map(a => Number(a.player_id)));
      for (const p of allPlayers) {
        if (!assigned.has(p.player_id)) groupMap.get(0).push(p.player_id);
      }
    } else {
      // Auto-split: top N players per slice (snake draft would be overkill — simple split)
      const perGroup = Math.ceil(allPlayers.length / N);
      allPlayers.forEach((p, i) => {
        const gi = Math.min(Math.floor(i / perGroup), N - 1);
        groupMap.get(gi).push(p.player_id);
      });
    }

    // ── Generate schedule per group ───────────────────────────────────────────
    // For each group: randomly pair players each round with no repeat opponents.
    // If odd players, one player gets a bye that round (rotated).
    // Each pairing produces matchesPerRound individual match rows.
    const matchRows = []; // { group_idx, round_num, match_num, p1_id, p2_id, is_bye }

    for (const [gi, playerIds] of groupMap) {
      if (!playerIds.length) continue;

      // Per-group config, falling back to tournament defaults
      const gcfg          = groupCfgMap.get(gi) || {};
      const rounds          = gcfg.rounds          || defaultRounds;
      const matchesPerRound = gcfg.matchesPerRound || defaultMpo;

      // Build list of all required pairings: each player needs `rounds` opponents (no repeats)
      // We use a round-by-round random shuffle approach with bye rotation for odd groups.
      const hasBye   = playerIds.length % 2 === 1;
      const poolSize = hasBye ? playerIds.length + 1 : playerIds.length; // pad with null for bye slot
      const padded   = hasBye ? [...playerIds, null] : [...playerIds];

      // Track which opponents each player has already faced to avoid repeats
      const faced = new Map();
      for (const pid of playerIds) faced.set(pid, new Set());

      // Track bye rotation: who has had the fewest byes
      const byeCount = new Map();
      for (const pid of playerIds) byeCount.set(pid, 0);

      for (let round = 1; round <= rounds; round++) {
        // Attempt to build a valid pairing for this round (no repeats)
        // Up to 20 shuffle attempts before accepting best available
        let bestPairs = null;
        let bestConflicts = Infinity;

        for (let attempt = 0; attempt < 20; attempt++) {
          // Shuffle player pool (keeping null at end for bye if needed)
          const shuffled = [...playerIds].sort(() => Math.random() - 0.5);
          if (hasBye) {
            // Determine who gets the bye this round: player with fewest byes who hasn't faced bye yet
            // (bye is tracked as facing null)
            let byePlayer = null;
            let minByes = Infinity;
            for (const pid of shuffled) {
              const bc = byeCount.get(pid) || 0;
              if (bc < minByes) { minByes = bc; byePlayer = pid; }
            }
            // Move bye player to last position so they pair with the null slot
            const idx = shuffled.indexOf(byePlayer);
            shuffled.splice(idx, 1);
            shuffled.push(byePlayer);
          }

          // Pair up: [0,1], [2,3], ...
          const pairs = [];
          for (let i = 0; i < shuffled.length; i += 2) {
            pairs.push([shuffled[i], shuffled[i + 1] || null]);
          }
          if (hasBye) {
            // Last pair has the bye player vs null — ensure it's the one we wanted
            // Already guaranteed by how we moved byePlayer to end above
          }

          // Count conflicts (repeat opponents)
          let conflicts = 0;
          for (const [a, b] of pairs) {
            if (a && b && faced.get(a)?.has(b)) conflicts++;
          }
          if (conflicts < bestConflicts) {
            bestConflicts = conflicts;
            bestPairs     = pairs;
            if (conflicts === 0) break;
          }
        }

        // Commit pairings
        for (const [a, b] of bestPairs) {
          if (!a) continue; // skip null-null (shouldn't happen)
          const isBye = b === null;

          // Track faced
          if (!isBye) {
            faced.get(a)?.add(b);
            faced.get(b)?.add(a);
          } else {
            byeCount.set(a, (byeCount.get(a) || 0) + 1);
          }

          // Emit match rows: one per match_num (e.g. 3 rows for matchesPerRound=3)
          for (let mn = 1; mn <= matchesPerRound; mn++) {
            matchRows.push({
              group_idx: gi,
              round_num: round,
              match_num: mn,
              p1_id:     a,
              p2_id:     isBye ? null : b,
              is_bye:    isBye,
              is_makeup: false
            });
          }
        }
      }

      // ── Make-up round for odd-player groups ───────────────────────────────────
      // Every player who received a bye needs one real scoring round to make up for it.
      // Bye players are paired against each other (randomly, no repeat opponents).
      // If the bye pool is odd, the leftover "odd man out" is paired against the
      // closest-rated non-bye player they haven't faced — that opponent does not score
      // (is_makeup = true, p1 = bye player who scores, p2 = non-scoring body).
      if (hasBye) {
        const makeupRound = rounds + 1;

        // Collect all players who received at least one bye
        const byePlayers  = playerIds.filter(pid => (byeCount.get(pid) || 0) > 0);
        const nonByePlayers = playerIds.filter(pid => (byeCount.get(pid) || 0) === 0);

        // Build seed_rating lookup for this group (for odd-man-out closest rating search)
        const ratingResult = await pool.query(
          `SELECT rtp.player_id, rtp.seed_rating
           FROM roundrobin_tournament_players rtp
           WHERE rtp.tournament_id = $1 AND rtp.player_id = ANY($2::int[])`,
          [id, playerIds]
        );
        const ratingMap = new Map(ratingResult.rows.map(r => [r.player_id, +r.seed_rating || 0]));

        // Shuffle bye players and pair them — retry up to 20 times to avoid repeat opponents
        let byePairs = [];
        let oddManOut = null;

        for (let attempt = 0; attempt < 20; attempt++) {
          const shuffled = [...byePlayers].sort(() => Math.random() - 0.5);
          const pairs    = [];
          let conflict   = false;

          for (let i = 0; i < shuffled.length - 1; i += 2) {
            const a = shuffled[i];
            const b = shuffled[i + 1];
            if (faced.get(a)?.has(b)) { conflict = true; break; }
            pairs.push([a, b]);
          }

          if (!conflict) {
            byePairs   = pairs;
            oddManOut  = shuffled.length % 2 === 1 ? shuffled[shuffled.length - 1] : null;
            break;
          }

          // Last attempt — accept best available even with a conflict
          if (attempt === 19) {
            byePairs  = [];
            const sh2 = [...byePlayers].sort(() => Math.random() - 0.5);
            for (let i = 0; i < sh2.length - 1; i += 2) byePairs.push([sh2[i], sh2[i + 1]]);
            oddManOut = sh2.length % 2 === 1 ? sh2[sh2.length - 1] : null;
          }
        }

        // Emit make-up match rows for paired bye players (both score normally)
        for (const [a, b] of byePairs) {
          faced.get(a)?.add(b);
          faced.get(b)?.add(a);
          for (let mn = 1; mn <= matchesPerRound; mn++) {
            matchRows.push({
              group_idx: gi,
              round_num: makeupRound,
              match_num: mn,
              p1_id:     a,
              p2_id:     b,
              is_bye:    false,
              is_makeup: false
            });
          }
        }

        // Emit make-up match row for odd man out — find closest-rated non-bye opponent
        // they haven't faced; fall back to closest rated if all have been faced already
        if (oddManOut !== null) {
          const oomRating = ratingMap.get(oddManOut) || 0;

          // Sort non-bye players by rating proximity to odd man out
          const candidates = [...nonByePlayers].sort((a, b) =>
            Math.abs(ratingMap.get(a) - oomRating) - Math.abs(ratingMap.get(b) - oomRating)
          );

          // Prefer someone not yet faced; fall back to closest regardless
          const body =
            candidates.find(pid => !faced.get(oddManOut)?.has(pid)) ||
            candidates[0] ||
            null;

          if (body !== null) {
            for (let mn = 1; mn <= matchesPerRound; mn++) {
              matchRows.push({
                group_idx: gi,
                round_num: makeupRound,
                match_num: mn,
                p1_id:     oddManOut,  // bye player — scores
                p2_id:     body,       // non-bye body — does not score
                is_bye:    false,
                is_makeup: true
              });
            }
          }
        }
      }
    }

    // ── Persist in a transaction ──────────────────────────────────────────────
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Update group_idx on each player row
      for (const [gi, playerIds] of groupMap) {
        if (!playerIds.length) continue;
        await client.query(
          `UPDATE roundrobin_tournament_players SET group_idx = $1
           WHERE tournament_id = $2 AND player_id = ANY($3::int[])`,
          [gi, id, playerIds]
        );
      }

      // Delete any previously generated matches
      await client.query(`DELETE FROM roundrobin_matches WHERE tournament_id = $1`, [id]);

      // Bulk insert matches
      for (const m of matchRows) {
        await client.query(
          `INSERT INTO roundrobin_matches
             (tournament_id, group_idx, round_num, match_num, p1_id, p2_id, is_bye, is_makeup, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW(), NOW())`,
          [id, m.group_idx, m.round_num, m.match_num, m.p1_id, m.p2_id || null, m.is_bye, m.is_makeup || false]
        );
      }

      // Transition to running
      await client.query(
        `UPDATE roundrobin_tournaments SET status = 'running', updated_at = NOW() WHERE tournament_id = $1`,
        [id]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // Return the matches with player names joined
    const matchResult = await pool.query(
      `SELECT m.match_id, m.group_idx, m.round_num, m.match_num,
              m.p1_id, m.p2_id, m.is_bye, m.is_makeup, m.status,
              p1.first_name AS p1_first, p1.last_name AS p1_last,
              p1.hall_rating AS p1_rating,
              p2.first_name AS p2_first, p2.last_name AS p2_last,
              p2.hall_rating AS p2_rating
       FROM roundrobin_matches m
       JOIN player p1 ON m.p1_id = p1.player_id
       LEFT JOIN player p2 ON m.p2_id = p2.player_id
       WHERE m.tournament_id = $1
       ORDER BY m.group_idx, m.round_num, m.match_id`,
      [id]
    );

    res.status(201).json({
      message: `Schedule generated: ${matchRows.length} match rows across ${N} group(s)`,
      matches: matchResult.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/roundrobin-tournaments/:id/matches ──────────────────────────────
app.get('/hall/roundrobin-tournaments/:id/matches', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const tCheck = await pool.query(
      `SELECT tournament_id FROM roundrobin_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (tCheck.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });

    const result = await pool.query(
      `SELECT m.match_id, m.group_idx, m.round_num, m.match_num,
              m.p1_id, m.p2_id, m.is_bye, m.is_makeup, m.status, m.winner_id, m.score1, m.score2,
              p1.first_name AS p1_first, p1.last_name AS p1_last,
              p1.hall_rating AS p1_rating,
              p2.first_name AS p2_first, p2.last_name AS p2_last,
              p2.hall_rating AS p2_rating
       FROM roundrobin_matches m
       JOIN player p1 ON m.p1_id = p1.player_id
       LEFT JOIN player p2 ON m.p2_id = p2.player_id
       WHERE m.tournament_id = $1
       ORDER BY m.group_idx, m.round_num, m.match_id`,
      [id]
    );
    res.json({ matches: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LEAGUE ENDPOINTS (Phase 1 — league CRUD + teams + roster)
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /hall/leagues ─────────────────────────────────────────────────────────
// List all leagues for this hall, with team count included.
app.get('/hall/leagues', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.id, l.name, l.season_label, l.status, l.playing_day,
              l.start_date, l.end_date, l.num_weeks,
              l.players_per_team, l.matches_per_night,
              l.has_playoffs, l.playoff_format,
              l.created_at, l.updated_at,
              COUNT(t.id)::int AS team_count
       FROM leagues l
       LEFT JOIN teams t ON t.league_id = l.id
       WHERE l.poolhall_id = $1
       GROUP BY l.id
       ORDER BY l.created_at DESC`,
      [req.hallId]
    );
    res.json({ leagues: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/leagues ────────────────────────────────────────────────────────
// Create a new league. Body contains all config fields from the setup wizard.
app.post('/hall/leagues', requireAuth, requireHallAdmin, async (req, res) => {
  const {
    name, season_label, playing_day, start_date, end_date, num_weeks,
    custom_dates, skip_dates, players_per_team, matches_per_night,
    preferred_rating_type, rating_enforcement, win_condition,
    tiebreaker_order, bye_handling, has_playoffs, playoff_format,
    leaderboard_default, player_lb_default
  } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'League name is required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO leagues (
         poolhall_id, name, season_label, status, playing_day,
         start_date, end_date, num_weeks, custom_dates, skip_dates,
         players_per_team, matches_per_night, preferred_rating_type,
         rating_enforcement, win_condition, tiebreaker_order,
         bye_handling, has_playoffs, playoff_format,
         leaderboard_default, player_lb_default,
         created_at, updated_at, created_by
       ) VALUES (
         $1,$2,$3,'draft',$4,
         $5,$6,$7,$8,$9,
         $10,$11,$12,
         $13,$14,$15,
         $16,$17,$18,
         $19,$20,
         NOW(),NOW(),$21
       )
       RETURNING *`,
      [
        req.hallId,
        name.trim(),
        season_label || null,
        playing_day || null,
        start_date || null,
        end_date || null,
        num_weeks || null,
        custom_dates ? JSON.stringify(custom_dates) : null,
        skip_dates ? JSON.stringify(skip_dates) : null,
        players_per_team || 5,
        matches_per_night || 5,
        preferred_rating_type || 'rating',
        rating_enforcement || 'warn',
        win_condition || 'games_won',
        tiebreaker_order ? JSON.stringify(tiebreaker_order) : JSON.stringify(['wins','points','head_to_head','playoff']),
        bye_handling || 'no_points',
        has_playoffs === true || has_playoffs === 'true' ? true : false,
        playoff_format || null,
        leaderboard_default || 'wins',
        player_lb_default || 'wins',
        req.user.user_id
      ]
    );
    res.status(201).json({ league: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/leagues/:id ─────────────────────────────────────────────────────
// Fetch a single league with its teams and each team's player count.
app.get('/hall/leagues/:id', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const leagueResult = await pool.query(
      `SELECT * FROM leagues WHERE id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (leagueResult.rows.length === 0) return res.status(404).json({ error: 'League not found' });

    const teamsResult = await pool.query(
      `SELECT t.id, t.name, t.status, t.captain_user_id, t.backup_captain_id,
              t.created_at, t.updated_at,
              COUNT(tp.id)::int AS player_count
       FROM teams t
       LEFT JOIN team_players tp ON tp.team_id = t.id AND tp.left_date IS NULL
       WHERE t.league_id = $1
       GROUP BY t.id
       ORDER BY t.created_at ASC`,
      [id]
    );

    res.json({ league: leagueResult.rows[0], teams: teamsResult.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/leagues/:id ─────────────────────────────────────────────────────
// Update league config or status. Draft → active transition allowed here.
app.put('/hall/leagues/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const {
    name, season_label, status, playing_day, start_date, end_date, num_weeks,
    custom_dates, skip_dates, players_per_team, matches_per_night,
    preferred_rating_type, rating_enforcement, win_condition,
    tiebreaker_order, bye_handling, has_playoffs, playoff_format,
    leaderboard_default, player_lb_default, config
  } = req.body;

  const validStatuses = ['draft', 'active', 'completed', 'archived'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  }

  try {
    const check = await pool.query(
      `SELECT id FROM leagues WHERE id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'League not found' });

    const result = await pool.query(
      `UPDATE leagues SET
         name                  = COALESCE($1,  name),
         season_label          = COALESCE($2,  season_label),
         status                = COALESCE($3,  status),
         playing_day           = COALESCE($4,  playing_day),
         start_date            = COALESCE($5,  start_date),
         end_date              = COALESCE($6,  end_date),
         num_weeks             = COALESCE($7,  num_weeks),
         custom_dates          = COALESCE($8,  custom_dates),
         skip_dates            = COALESCE($9,  skip_dates),
         players_per_team      = COALESCE($10, players_per_team),
         matches_per_night     = COALESCE($11, matches_per_night),
         preferred_rating_type = COALESCE($12, preferred_rating_type),
         rating_enforcement    = COALESCE($13, rating_enforcement),
         win_condition         = COALESCE($14, win_condition),
         tiebreaker_order      = COALESCE($15, tiebreaker_order),
         bye_handling          = COALESCE($16, bye_handling),
         has_playoffs          = COALESCE($17, has_playoffs),
         playoff_format        = COALESCE($18, playoff_format),
         leaderboard_default   = COALESCE($19, leaderboard_default),
         player_lb_default     = COALESCE($20, player_lb_default),
         config                = COALESCE($21, config),
         updated_at            = NOW()
       WHERE id = $22 AND poolhall_id = $23
       RETURNING *`,
      [
        name || null, season_label || null, status || null, playing_day || null,
        start_date || null, end_date || null, num_weeks || null,
        custom_dates ? JSON.stringify(custom_dates) : null,
        skip_dates ? JSON.stringify(skip_dates) : null,
        players_per_team || null, matches_per_night || null,
        preferred_rating_type || null, rating_enforcement || null,
        win_condition || null,
        tiebreaker_order ? JSON.stringify(tiebreaker_order) : null,
        bye_handling || null,
        has_playoffs != null ? has_playoffs : null,
        playoff_format || null,
        leaderboard_default || null, player_lb_default || null,
        config ? JSON.stringify(config) : null,
        id, req.hallId
      ]
    );
    res.json({ league: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/leagues/:id ──────────────────────────────────────────────────
// Hard delete — only permitted on draft leagues (not active/completed/archived).
app.delete('/hall/leagues/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(
      `SELECT id, name, status FROM leagues WHERE id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'League not found' });
    if (check.rows[0].status !== 'draft') {
      return res.status(409).json({ error: 'Only draft leagues can be deleted' });
    }
    await pool.query(`DELETE FROM leagues WHERE id = $1`, [id]);
    console.log(`[LEAGUE DELETE] id=${id} name="${check.rows[0].name}" poolhall_id=${req.hallId} deleted_by=user_id:${req.user.user_id}`);
    res.json({ deleted: true, id: parseInt(id), name: check.rows[0].name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/leagues/:id/teams ───────────────────────────────────────────────
// List teams for a league, with current roster player count.
app.get('/hall/leagues/:id/teams', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const leagueCheck = await pool.query(
      `SELECT id FROM leagues WHERE id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (leagueCheck.rows.length === 0) return res.status(404).json({ error: 'League not found' });

    const result = await pool.query(
      `SELECT t.id, t.name, t.status, t.captain_user_id, t.backup_captain_id,
              t.created_at, t.updated_at,
              COUNT(tp.id)::int AS player_count
       FROM teams t
       LEFT JOIN team_players tp ON tp.team_id = t.id AND tp.left_date IS NULL
       WHERE t.league_id = $1
       GROUP BY t.id
       ORDER BY t.created_at ASC`,
      [id]
    );
    res.json({ teams: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/leagues/:id/teams ──────────────────────────────────────────────
// Create a team within a league.
app.post('/hall/leagues/:id/teams', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, captain_user_id, backup_captain_id } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Team name is required' });

  try {
    const leagueCheck = await pool.query(
      `SELECT id, status FROM leagues WHERE id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (leagueCheck.rows.length === 0) return res.status(404).json({ error: 'League not found' });
    if (leagueCheck.rows[0].status === 'archived') {
      return res.status(409).json({ error: 'Cannot add teams to an archived league' });
    }

    const result = await pool.query(
      `INSERT INTO teams (league_id, poolhall_id, name, status, captain_user_id, backup_captain_id, created_at, updated_at)
       VALUES ($1, $2, $3, 'active', $4, $5, NOW(), NOW())
       RETURNING id, league_id, name, status, captain_user_id, backup_captain_id, created_at, updated_at`,
      [id, req.hallId, name.trim(), captain_user_id || null, backup_captain_id || null]
    );
    res.status(201).json({ team: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A team with that name already exists in this league' });
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /hall/leagues/:id/teams/:teamId ───────────────────────────────────────
// Update team name, status, or captain assignments.
app.put('/hall/leagues/:id/teams/:teamId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, teamId } = req.params;
  const { name, status, captain_user_id, backup_captain_id } = req.body;
  const validStatuses = ['active', 'withdrawn'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` });
  }

  try {
    const check = await pool.query(
      `SELECT t.id FROM teams t
       JOIN leagues l ON l.id = t.league_id
       WHERE t.id = $1 AND t.league_id = $2 AND l.poolhall_id = $3`,
      [teamId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Team not found' });

    const result = await pool.query(
      `UPDATE teams SET
         name              = COALESCE($1, name),
         status            = COALESCE($2, status),
         captain_user_id   = COALESCE($3, captain_user_id),
         backup_captain_id = COALESCE($4, backup_captain_id),
         updated_at        = NOW()
       WHERE id = $5
       RETURNING id, league_id, name, status, captain_user_id, backup_captain_id, updated_at`,
      [name || null, status || null, captain_user_id || null, backup_captain_id || null, teamId]
    );
    res.json({ team: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/leagues/:id/teams/:teamId ────────────────────────────────────
// Remove a team. Only permitted on draft leagues; cascades to team_players.
app.delete('/hall/leagues/:id/teams/:teamId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, teamId } = req.params;
  try {
    const leagueCheck = await pool.query(
      `SELECT status FROM leagues WHERE id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (leagueCheck.rows.length === 0) return res.status(404).json({ error: 'League not found' });
    if (leagueCheck.rows[0].status !== 'draft') {
      return res.status(409).json({ error: 'Teams can only be removed from draft leagues' });
    }

    const result = await pool.query(
      `DELETE FROM teams WHERE id = $1 AND league_id = $2 RETURNING id, name`,
      [teamId, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Team not found' });
    res.json({ deleted: true, team: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /hall/leagues/:id/teams/:teamId/players ───────────────────────────────
// Fetch the current roster for a team (left_date IS NULL = active members).
app.get('/hall/leagues/:id/teams/:teamId/players', requireAuth, requireHallAuth, async (req, res) => {
  const { id, teamId } = req.params;
  try {
    const check = await pool.query(
      `SELECT t.id FROM teams t
       JOIN leagues l ON l.id = t.league_id
       WHERE t.id = $1 AND t.league_id = $2 AND l.poolhall_id = $3`,
      [teamId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Team not found' });

    const result = await pool.query(
      `SELECT tp.id, tp.player_id, tp.role, tp.joined_date,
              p.first_name, p.last_name, p.hall_rating, p.fargo_rating, p.tier
       FROM team_players tp
       JOIN player p ON p.player_id = tp.player_id
       WHERE tp.team_id = $1 AND tp.left_date IS NULL
       ORDER BY tp.role DESC, p.last_name, p.first_name`,
      [teamId]
    );
    res.json({ players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /hall/leagues/:id/teams/:teamId/players ──────────────────────────────
// Add a player to a team roster. Validates:
//   - Player belongs to this hall
//   - Player is not already on another team in the same league
app.post('/hall/leagues/:id/teams/:teamId/players', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, teamId } = req.params;
  const { player_id, role } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id is required' });
  const validRoles = ['regular', 'sub'];
  const playerRole = role || 'regular';
  if (!validRoles.includes(playerRole)) {
    return res.status(400).json({ error: `role must be one of: ${validRoles.join(', ')}` });
  }

  try {
    // Verify team exists in this hall's league
    const teamCheck = await pool.query(
      `SELECT t.id FROM teams t
       JOIN leagues l ON l.id = t.league_id
       WHERE t.id = $1 AND t.league_id = $2 AND l.poolhall_id = $3`,
      [teamId, id, req.hallId]
    );
    if (teamCheck.rows.length === 0) return res.status(404).json({ error: 'Team not found' });

    // Verify player belongs to this hall
    const playerCheck = await pool.query(
      `SELECT player_id FROM player WHERE player_id = $1 AND poolhall_id = $2 AND deleted_at IS NULL`,
      [player_id, req.hallId]
    );
    if (playerCheck.rows.length === 0) return res.status(404).json({ error: 'Player not found' });

    // Check player is not already on a different team in the same league
    const conflictCheck = await pool.query(
      `SELECT tp.id, t.name AS team_name
       FROM team_players tp
       JOIN teams t ON t.id = tp.team_id
       WHERE t.league_id = $1 AND tp.player_id = $2 AND tp.left_date IS NULL AND tp.team_id != $3`,
      [id, player_id, teamId]
    );
    if (conflictCheck.rows.length > 0) {
      return res.status(409).json({
        error: `Player is already on team "${conflictCheck.rows[0].team_name}" in this league`
      });
    }

    const result = await pool.query(
      `INSERT INTO team_players (team_id, player_id, role, joined_date)
       VALUES ($1, $2, $3, CURRENT_DATE)
       ON CONFLICT (team_id, player_id) DO UPDATE
         SET left_date = NULL, role = EXCLUDED.role, joined_date = CURRENT_DATE
       RETURNING id, team_id, player_id, role, joined_date`,
      [teamId, player_id, playerRole]
    );
    if (!result.rows.length) return res.status(409).json({ error: 'Player already on this team' });
    res.status(201).json({ player: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/leagues/:id/teams/:teamId/players/:playerId ──────────────────
// Remove a player from a team. Sets left_date rather than hard deleting,
// preserving the record for any matches already played.
app.delete('/hall/leagues/:id/teams/:teamId/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, teamId, playerId } = req.params;
  try {
    const teamCheck = await pool.query(
      `SELECT t.id FROM teams t
       JOIN leagues l ON l.id = t.league_id
       WHERE t.id = $1 AND t.league_id = $2 AND l.poolhall_id = $3`,
      [teamId, id, req.hallId]
    );
    if (teamCheck.rows.length === 0) return res.status(404).json({ error: 'Team not found' });

    const result = await pool.query(
      `UPDATE team_players SET left_date = CURRENT_DATE
       WHERE team_id = $1 AND player_id = $2 AND left_date IS NULL
       RETURNING id, player_id, left_date`,
      [teamId, playerId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Player not on this team' });
    res.json({ removed: true, player: result.rows[0] });
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
        await upsertTryLeagueStats(client, id, row.poolhall_id);
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

// ── PUT /hall/tryleague-sessions/:id/pin ─────────────────────────────────────
// Update captain PIN only — leaves all other config fields untouched.
// No status restriction — valid for setup, running, or finished sessions.
app.put('/hall/tryleague-sessions/:id/pin', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const { pin } = req.body;
  if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  try {
    const result = await pool.query(
      `UPDATE tryleague_sessions
       SET config = jsonb_set(config, '{captain_pin}', $1::jsonb)
       WHERE session_id = $2 AND poolhall_id = $3
       RETURNING session_id, name, config`,
      [JSON.stringify(pin), id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
    res.json({ session: result.rows[0] });
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

// ── POST /public/tryleague-sessions/:id/verify-pin ───────────────────────────
// No auth required. Validates captain PIN against session config.
// Rate-limited via existing checkRateLimit(). Only accepts running sessions.
app.post('/public/tryleague-sessions/:id/verify-pin', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });

  const { id } = req.params;
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'pin is required' });

  try {
    const result = await pool.query(
      `SELECT config FROM tryleague_sessions WHERE session_id = $1 AND status = 'running'`,
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Session not found or not running' });

    const config = result.rows[0].config || {};
    const storedPin = config.captain_pin;
    if (!storedPin) return res.status(403).json({ error: 'No PIN set for this session' });

    if (String(pin).trim() === String(storedPin).trim()) {
      res.json({ valid: true });
    } else {
      res.status(403).json({ valid: false, error: 'Incorrect PIN' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /public/tryleague-sessions/:id/matches/:matchId ──────────────────────
// No JWT required. PIN in request body acts as auth.
// Captains may only set status 'done' — cannot re-open or reset matches.
// Session must be 'running'. PIN must match config.captain_pin.
app.put('/public/tryleague-sessions/:id/matches/:matchId', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });

  const { id, matchId } = req.params;
  const { pin, score1, score2, winner_id } = req.body;
  if (!pin) return res.status(400).json({ error: 'pin is required' });

  try {
    // Validate session is running and PIN matches
    const sessionResult = await pool.query(
      `SELECT config FROM tryleague_sessions WHERE session_id = $1 AND status = 'running'`,
      [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found or not running' });

    const config = sessionResult.rows[0].config || {};
    const storedPin = config.captain_pin;
    if (!storedPin) return res.status(403).json({ error: 'No PIN set for this session' });
    if (String(pin).trim() !== String(storedPin).trim()) return res.status(403).json({ error: 'Incorrect PIN' });

    // Validate match belongs to this session
    const matchCheck = await pool.query(
      `SELECT match_id, status FROM tryleague_matches WHERE match_id = $1 AND session_id = $2`,
      [matchId, id]
    );
    if (matchCheck.rows.length === 0) return res.status(404).json({ error: 'Match not found' });

    // Validate scores: one must be 10–17 (winner), other 0–7 (loser), total = 17
    const s1 = score1 != null ? parseInt(score1) : null;
    const s2 = score2 != null ? parseInt(score2) : null;
    if (s1 == null || s2 == null || isNaN(s1) || isNaN(s2)) return res.status(400).json({ error: 'score1 and score2 are required' });
    if (s1 + s2 !== 17) return res.status(400).json({ error: 'Scores must total 17' });
    const validPair = (s1 >= 10 && s2 <= 7) || (s2 >= 10 && s1 <= 7);
    if (!validPair) return res.status(400).json({ error: 'Invalid scores — winner needs 10–17, loser 0–7' });
    if (!winner_id) return res.status(400).json({ error: 'winner_id is required' });

    const result = await pool.query(
      `UPDATE tryleague_matches
       SET status = 'done', score1 = $1, score2 = $2, winner_id = $3, finished_at = NOW()
       WHERE match_id = $4 AND session_id = $5
       RETURNING match_id, session_id, group_idx, round_num, is_rotate,
                 p1_id, p2_id, winner_id, score1, score2, status, finished_at`,
      [s1, s2, winner_id, matchId, id]
    );
    res.json({ match: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Shared helper: finish a Try League session and upsert lifetime stats ──────
// PRE-REQUISITE MIGRATION (run once before deploying):
//   ALTER TABLE tryleague_player_stats ADD COLUMN IF NOT EXISTS total_points INT DEFAULT 0;
//
// BACKFILL (run once after migration to populate historical data):
//   UPDATE tryleague_player_stats tps
//   SET total_points = sub.pts
//   FROM (
//     SELECT
//       CASE WHEN m.winner_id = m.p1_id THEN m.p1_id ELSE m.p2_id END AS player_id,
//       sp.poolhall_id,
//       SUM(CASE WHEN m.p1_id = CASE WHEN m.winner_id = m.p1_id THEN m.p1_id ELSE m.p2_id END
//                THEN m.score1 ELSE m.score2 END) AS pts
//     FROM tryleague_matches m
//     JOIN tryleague_session_players sp
//       ON sp.session_id = m.session_id
//      AND sp.player_id = CASE WHEN m.winner_id = m.p1_id THEN m.p1_id ELSE m.p2_id END
//     WHERE m.status = 'done'
//       AND m.score1 IS NOT NULL
//       AND NOT (m.is_rotate = TRUE AND m.p2_id = CASE WHEN m.winner_id = m.p1_id THEN m.p1_id ELSE m.p2_id END)
//     GROUP BY CASE WHEN m.winner_id = m.p1_id THEN m.p1_id ELSE m.p2_id END, sp.poolhall_id
//   ) sub
//   WHERE tps.player_id = sub.player_id AND tps.poolhall_id = sub.poolhall_id;
//
// Accepts a pg client (for transaction support), sessionId, and poolhallId.
async function upsertTryLeagueStats(client, sessionId, poolhallId) {
  // Fetch all scored matches for this session.
  // Rotate matches: W/L counted for the non-double player only (identified at runtime).
  // Points: rotate matches excluded entirely from personal stats — only non-rotate matches count.
  const matches = await client.query(
    `SELECT p1_id, p2_id, winner_id, is_rotate, score1, score2
     FROM tryleague_matches
     WHERE session_id = $1 AND status = 'done' AND winner_id IS NOT NULL AND score1 IS NOT NULL`,
    [sessionId]
  );

  // Find the rotate double per round: the player appearing in both a rotate AND a normal match
  // in this session. Their rotate appearance doesn't count for personal W/L or points.
  const normalMatchPlayerIds = new Set();
  for (const m of matches.rows) {
    if (!m.is_rotate) {
      normalMatchPlayerIds.add(m.p1_id);
      normalMatchPlayerIds.add(m.p2_id);
    }
  }

  const statsMap = new Map(); // player_id → { wins, losses, points }

  const ensure = (id) => {
    if (!statsMap.has(id)) statsMap.set(id, { wins: 0, losses: 0, points: 0 });
  };

  for (const m of matches.rows) {
    const winnerId  = m.winner_id;
    const loserId   = m.winner_id === m.p1_id ? m.p2_id : m.p1_id;
    const winScore  = m.winner_id === m.p1_id ? m.score1 : m.score2;
    const loseScore = m.winner_id === m.p1_id ? m.score2 : m.score1;

    if (m.is_rotate) {
      // The rotate double is whichever player also appears in normal matches.
      // Count W/L for the non-double player only. Points excluded for both on rotate matches.
      const doubleId   = normalMatchPlayerIds.has(m.p1_id) ? m.p1_id : m.p2_id;
      const nonDoubleId = m.p1_id === doubleId ? m.p2_id : m.p1_id;
      ensure(nonDoubleId);
      if (m.winner_id === nonDoubleId) statsMap.get(nonDoubleId).wins   += 1;
      else                             statsMap.get(nonDoubleId).losses  += 1;
      // No points for rotate matches
    } else {
      ensure(winnerId);
      ensure(loserId);
      statsMap.get(winnerId).wins   += 1;
      statsMap.get(winnerId).points += winScore;
      statsMap.get(loserId).losses  += 1;
      statsMap.get(loserId).points  += loseScore;
    }
  }

  for (const [playerId, delta] of statsMap.entries()) {
    await client.query(
      `INSERT INTO tryleague_player_stats (player_id, poolhall_id, sessions_played, total_wins, total_losses, total_points, last_played_at)
       VALUES ($1, $2, 1, $3, $4, $5, NOW())
       ON CONFLICT (player_id, poolhall_id) DO UPDATE SET
         sessions_played = tryleague_player_stats.sessions_played + 1,
         total_wins      = tryleague_player_stats.total_wins      + EXCLUDED.total_wins,
         total_losses    = tryleague_player_stats.total_losses    + EXCLUDED.total_losses,
         total_points    = tryleague_player_stats.total_points    + EXCLUDED.total_points,
         last_played_at  = NOW()`,
      [playerId, poolhallId, delta.wins, delta.losses, delta.points]
    );
  }

  // Ensure every roster player gets a sessions_played increment even if they had no scored matches
  const allRoster = await client.query(
    `SELECT player_id FROM tryleague_session_players WHERE session_id = $1`, [sessionId]
  );
  for (const rp of allRoster.rows) {
    if (!statsMap.has(rp.player_id)) {
      await client.query(
        `INSERT INTO tryleague_player_stats (player_id, poolhall_id, sessions_played, total_wins, total_losses, total_points, last_played_at)
         VALUES ($1, $2, 1, 0, 0, 0, NOW())
         ON CONFLICT (player_id, poolhall_id) DO UPDATE SET
           sessions_played = tryleague_player_stats.sessions_played + 1,
           last_played_at  = NOW()`,
        [rp.player_id, poolhallId]
      );
    }
  }

  console.log(`Session ${sessionId} finished: stats upserted for ${statsMap.size} players, ${allRoster.rows.length} total roster`);
}

// ── PUT /public/tryleague-sessions/:id/finish ─────────────────────────────────
// No JWT required. PIN in request body acts as auth.
// Validates all non-rotate matches are done, then marks session finished and upserts stats.
// Idempotent: if already finished returns 200 with no side-effects.
app.put('/public/tryleague-sessions/:id/finish', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });

  const { id } = req.params;
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'pin is required' });

  try {
    const sessionResult = await pool.query(
      `SELECT session_id, status, config, poolhall_id, started_at, finished_at
       FROM tryleague_sessions WHERE session_id = $1`,
      [id]
    );
    if (sessionResult.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

    const session = sessionResult.rows[0];

    // Idempotent — already finished
    if (session.status === 'finished') return res.json({ session });

    if (session.status !== 'running') return res.status(409).json({ error: 'Session is not running' });

    const config = session.config || {};
    const storedPin = config.captain_pin;
    if (!storedPin) return res.status(403).json({ error: 'No PIN set for this session' });
    if (String(pin).trim() !== String(storedPin).trim()) return res.status(403).json({ error: 'Incorrect PIN' });

    // Verify all non-rotate matches are done
    const pendingCheck = await pool.query(
      `SELECT COUNT(*) AS cnt FROM tryleague_matches
       WHERE session_id = $1 AND is_rotate = FALSE AND status != 'done'`,
      [id]
    );
    if (parseInt(pendingCheck.rows[0].cnt) > 0) {
      return res.status(409).json({ error: 'Not all matches are complete' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const finished_at = new Date();
      const result = await client.query(
        `UPDATE tryleague_sessions SET status = 'finished', finished_at = $1
         WHERE session_id = $2
         RETURNING session_id, poolhall_id, name, status, config, created_at, started_at, finished_at`,
        [finished_at, id]
      );
      await upsertTryLeagueStats(client, id, session.poolhall_id);
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

// ── GET /public/poolhalls/:publicId/tl-player-stats ───────────────────────────
// No auth required. Returns lifetime Try League stats for all players at a hall.
// Identified by the hall's public_id (opaque 12-char token, not the internal poolhall_id).
app.get('/public/poolhalls/:publicId/tl-player-stats', async (req, res) => {
  const { publicId } = req.params;
  try {
    const hallResult = await pool.query(
      `SELECT poolhall_id, poolhall_name FROM poolhall WHERE public_id = $1`,
      [publicId]
    );
    if (hallResult.rows.length === 0) return res.status(404).json({ error: 'Hall not found' });

    const { poolhall_id, poolhall_name } = hallResult.rows[0];

    const result = await pool.query(
      `SELECT
         p.player_id,
         p.first_name,
         p.last_name,
         p.tier,
         p.fargo_rating,
         p.hall_rating,
         COALESCE(s.sessions_played, 0) AS sessions_played,
         COALESCE(s.total_wins,      0) AS total_wins,
         COALESCE(s.total_losses,    0) AS total_losses,
         COALESCE(s.total_points,    0) AS total_points,
         s.last_played_at
       FROM player p
       LEFT JOIN tryleague_player_stats s
         ON s.player_id = p.player_id AND s.poolhall_id = $1
       WHERE p.poolhall_id = $1
         AND p.deleted_at IS NULL
         AND (s.sessions_played > 0 OR s.player_id IS NOT NULL)
       ORDER BY s.total_wins DESC NULLS LAST, p.last_name, p.first_name`,
      [poolhall_id]
    );

    res.json({
      poolhall_name,
      players: result.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
