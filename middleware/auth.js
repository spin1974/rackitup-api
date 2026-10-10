// middleware/auth.js — JWT + role middleware (moved verbatim out of server.js, 2026-10-10).
require('dotenv').config();
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

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

module.exports = { requireAuth, requireSiteAdmin, requireHallAuth, requireHallAdmin };
