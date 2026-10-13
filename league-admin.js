// routes/league-admin.js — League Format: delete a league at any status (password-confirmed). Added 2026-10-12.
// Mounted from server.js with:  app.use(require('./routes/league-admin'));   (next to the chip mount)
//
// Replaces the old draft-only `DELETE /hall/leagues/:id` that lived in server.js (that block is removed in the same change).
//
//   GET    /hall/leagues/:id/delete-preview   hall_admin   what would be removed (counts) + whether it can be deleted
//   DELETE /hall/leagues/:id                  hall_admin   body { password } — the caller's OWN password, re-entered
//
// Rules (Chris, 2026-10-12): a league can be deleted whatever its status (test leftovers that were never competed are noise),
// but only after the signed-in user re-enters their password. The one exception: an ARCHIVED league that has a
// league_archive_summary row stays undeletable — that table is `ON DELETE RESTRICT` on purpose ("archived seasons are
// permanent record"), so it is refused up front with a clear message instead of surfacing a raw FK error.
//
// WRONG PASSWORD RETURNS 403, NEVER 401. The frontend's apiFetch() treats every 401 as an expired session and redirects to
// the login page, so a typo would log the user out of the page. 400 = missing/invalid input, 403 = wrong password,
// 404 = no such league in this hall, 409 = archived, 429 = too many wrong passwords.
//
// Everything a league owns is removed by the existing ON DELETE CASCADE foreign keys from `leagues` (nights, matchups,
// results, substitutions, captains, standings, player stats, rating snapshots, teams, team_players, schedule drafts).
// league_matchups -> teams is NO ACTION, but it is checked at the END of the statement, by which time the same statement
// has cascaded the matchups away too. Players themselves (the `player` table) are never touched.
//
// The deletion is written to event_audit_log (event_type 'league', action 'deleted' — both already allowed by the CHECK
// constraints, no migration) inside the same transaction as the delete, with a snapshot of the league and its counts.
const express = require('express');
const bcrypt  = require('bcrypt');
const router  = express.Router();

const pool = require('../db');
const { requireAuth, requireHallAdmin } = require('../middleware/auth');
const { logEventAudit } = require('../lib/audit');

// ── Wrong-password limiter ───────────────────────────────────────────────────
// Keyed by user id (not IP: a whole hall shares one public IP). Only FAILED attempts count, and a success clears the
// record. 5 wrong passwords in 15 minutes locks this route for that user until the window passes. Process memory only —
// a restart clears it, which is fine for a guard against someone guessing at a stolen session.
const MAX_BAD_PASSWORDS = 5;
const BAD_PW_WINDOW_MS  = 15 * 60 * 1000;
const badPasswords = new Map();   // user_id -> { count, windowStart }

function isLockedOut(userId) {
  const rec = badPasswords.get(userId);
  if (!rec) return false;
  if (Date.now() - rec.windowStart > BAD_PW_WINDOW_MS) { badPasswords.delete(userId); return false; }
  return rec.count >= MAX_BAD_PASSWORDS;
}
function recordBadPassword(userId) {
  const now = Date.now();
  const rec = badPasswords.get(userId);
  if (!rec || now - rec.windowStart > BAD_PW_WINDOW_MS) badPasswords.set(userId, { count: 1, windowStart: now });
  else rec.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [uid, rec] of badPasswords.entries()) if (now - rec.windowStart > BAD_PW_WINDOW_MS) badPasswords.delete(uid);
}, BAD_PW_WINDOW_MS).unref();

// ── Helpers ──────────────────────────────────────────────────────────────────
function parseId(raw) {
  return /^\d+$/.test(String(raw)) ? parseInt(raw, 10) : null;
}

// Counts of everything the delete would remove. `db` is the pool or an in-transaction client.
async function leagueImpact(db, leagueId) {
  const r = await db.query(
    `SELECT
       (SELECT COUNT(*) FROM teams WHERE league_id = $1)                                                    AS teams,
       (SELECT COUNT(*) FROM team_players tp JOIN teams t ON t.id = tp.team_id WHERE t.league_id = $1)      AS roster_entries,
       (SELECT COUNT(*) FROM league_nights WHERE league_id = $1)                                            AS nights,
       (SELECT COUNT(*) FROM league_nights WHERE league_id = $1 AND status = 'completed')                   AS nights_completed,
       (SELECT COUNT(*) FROM league_matchups WHERE league_id = $1 AND is_bye = false)                       AS matchups,
       (SELECT COUNT(*) FROM league_matchups WHERE league_id = $1 AND is_bye = false AND status <> 'pending') AS matchups_started,
       (SELECT COUNT(*) FROM league_matchup_results r JOIN league_matchups m ON m.id = r.league_matchup_id
          WHERE m.league_id = $1)                                                                           AS score_rows,
       (SELECT COUNT(*) FROM league_standings WHERE league_id = $1)                                         AS standings_rows,
       (SELECT COUNT(*) FROM player_league_stats WHERE league_id = $1)                                      AS player_stat_rows,
       (SELECT COUNT(*) FROM league_matchup_drafts WHERE league_id = $1)                                    AS schedule_draft_rows`,
    [leagueId]
  );
  const out = {};
  for (const [k, v] of Object.entries(r.rows[0])) out[k] = parseInt(v, 10);
  return out;
}

async function hasArchiveSummary(db, leagueId) {
  const r = await db.query(`SELECT 1 FROM league_archive_summary WHERE league_id = $1 LIMIT 1`, [leagueId]);
  return r.rows.length > 0;
}

const ARCHIVED_MSG = 'This league has been archived and its season summary is kept as a permanent record, so it cannot be deleted.';

// ── GET /hall/leagues/:id/delete-preview ─────────────────────────────────────
router.get('/hall/leagues/:id/delete-preview', requireAuth, requireHallAdmin, async (req, res) => {
  const id = parseId(req.params.id);
  if (id === null) return res.status(400).json({ error: 'Invalid league id' });
  try {
    const lg = await pool.query(
      `SELECT id, name, season_label, status FROM leagues WHERE id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (lg.rows.length === 0) return res.status(404).json({ error: 'League not found' });
    const archived = await hasArchiveSummary(pool, id);
    const impact   = await leagueImpact(pool, id);
    res.json({
      league: lg.rows[0],
      deletable: !archived,
      blocked_reason: archived ? ARCHIVED_MSG : null,
      impact
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /hall/leagues/:id ─────────────────────────────────────────────────
router.delete('/hall/leagues/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const id = parseId(req.params.id);
  if (id === null) return res.status(400).json({ error: 'Invalid league id' });

  const password = req.body && req.body.password;
  if (typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'Your password is required to delete a league', code: 'password_required' });
  }

  const userId = req.user.user_id;
  let client;
  try {
    // 1) the league must exist in THIS hall
    const lg = await pool.query(
      `SELECT id, name, season_label, status, playing_day, start_date, end_date, num_weeks, schedule_type
         FROM leagues WHERE id = $1 AND poolhall_id = $2`,
      [id, req.hallId]
    );
    if (lg.rows.length === 0) return res.status(404).json({ error: 'League not found' });
    const league = lg.rows[0];

    // 2) archived-with-summary is permanent
    if (await hasArchiveSummary(pool, id)) {
      return res.status(409).json({ error: ARCHIVED_MSG, code: 'archived' });
    }

    // 3) re-entered password — the signed-in user's own
    if (isLockedOut(userId)) {
      return res.status(429).json({ error: 'Too many incorrect passwords. Try again in a few minutes.', code: 'locked' });
    }
    const u = await pool.query(
      `SELECT user_password FROM users WHERE user_id = $1 AND deleted_at IS NULL`,
      [userId]
    );
    if (u.rows.length === 0) return res.status(403).json({ error: 'Incorrect password', code: 'bad_password' });
    const ok = await bcrypt.compare(password, u.rows[0].user_password);
    if (!ok) {
      recordBadPassword(userId);
      return res.status(403).json({ error: 'Incorrect password', code: 'bad_password' });
    }
    badPasswords.delete(userId);

    // 4) delete + audit row, atomically
    client = await pool.connect();
    await client.query('BEGIN');
    const locked = await client.query(
      `SELECT id FROM leagues WHERE id = $1 AND poolhall_id = $2 FOR UPDATE`, [id, req.hallId]
    );
    if (locked.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'League not found' }); }
    const impact = await leagueImpact(client, id);
    await client.query(`DELETE FROM leagues WHERE id = $1 AND poolhall_id = $2`, [id, req.hallId]);
    await logEventAudit(client, {
      poolhallId: req.hallId, eventType: 'league', eventId: id, action: 'deleted', req,
      snapshot: league,
      detail: { impact, deleted_status: league.status }
    });
    await client.query('COMMIT');

    console.log(`[LEAGUE DELETE] id=${id} name="${league.name}" status=${league.status} poolhall_id=${req.hallId} deleted_by=user_id:${userId}`);
    res.json({ deleted: true, id, name: league.name, status: league.status, impact });
  } catch (err) {
    if (client) { try { await client.query('ROLLBACK'); } catch (_) { /* already aborted */ } }
    // 23001 restrict_violation / 23503 foreign_key_violation: something outside the cascade chain still references it
    if (err.code === '23001' || err.code === '23503') {
      return res.status(409).json({ error: 'This league is still referenced by other records and cannot be deleted.', code: 'referenced' });
    }
    res.status(500).json({ error: err.message });
  } finally {
    if (client) client.release();
  }
});

module.exports = router;
