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

    // Soft-deleted users cannot log in
    if (user.deleted_at) return res.status(401).json({ error: GENERIC });

    // Lockout check
    if (user.locked_at) {
      const minutesElapsed = (now - new Date(user.locked_at)) / 1000 / 60;
      if (minutesElapsed < LOCKOUT_MINUTES) {
        return res.status(401).json({ error: GENERIC });
      }
      // Auto-unlock silently
      await pool.query(
        `UPDATE users SET locked_at = NULL, failed_attempts = 0, updated_at = NOW() WHERE user_id = $1`,
        [user.user_id]
      );
      user.locked_at = null;
      user.failed_attempts = 0;
    }

    // Password check
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

    // Success — reset lockout state and record login time
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
        (SELECT COUNT(*) FROM player)                            AS player_count
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
  // Prevent deleting your own account
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
          postal_code, country, phone_number, primary_email, website)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
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

app.listen(PORT, () => {
  console.log(`Rack It Up API running on port ${PORT}`);
});
