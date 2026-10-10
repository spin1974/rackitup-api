// lib/audit.js — event_audit_log helper (moved verbatim out of server.js, 2026-10-10).

// ── Event audit log helper ─────────────────────────────────────────────────────
// Writes to the generic event_audit_log table (see migrations/2026-08-16_event_audit_log.sql).
// Accepts either `pool` or an in-transaction `client` as dbClient so callers already inside a
// BEGIN/COMMIT block can log atomically with the action itself.
// Never throws — a logging failure must not break the primary action it's describing.
//
// ── SAVEPOINT hardening (2026-09-06) — read before touching this ──────────────
// "Never throws" is necessary but NOT sufficient when dbClient is an in-transaction
// client. A failed INSERT puts Postgres into an aborted-transaction state; swallowing
// the error here means the caller never learns, and COMMIT on an aborted transaction
// is silently downgraded to ROLLBACK rather than raising. The caller's real work
// therefore vanishes while the route returns success.
//
// This bit for real: Round Robin's schedule route logged a 'schedule_generated'
// action that the CHECK constraint didn't allow yet. All 75 generated match rows and
// the group_idx updates were rolled back, and the API still returned 201 with
// "Schedule generated: 75 match rows". Nothing in the logs or the response said
// otherwise — the only tell was the empty matches array in the response body.
//
// Wrapping the INSERT in a SAVEPOINT contains the damage: a rejected audit write
// rolls back only itself, and the caller's transaction stays committable. Without
// this, the next unrecognised action value or NOT NULL miss re-arms the same trap
// on any caller that passes a client (Try League's PUT does too).
async function logEventAudit(dbClient, { poolhallId, eventType, eventId, action, req, snapshot, detail }) {
  // A pg PoolClient has .release(); the Pool itself does not. Only a client can
  // hold a SAVEPOINT — issuing one on the pool would land on an arbitrary
  // connection outside any transaction.
  const inTransaction = !!(dbClient && typeof dbClient.release === 'function');
  const SP = 'audit_log_sp';
  try {
    const performedByUserId = (req && req.user) ? req.user.user_id : null;
    const performedByRole   = (req && req.user) ? req.user.role_name : null;

    if (inTransaction) await dbClient.query(`SAVEPOINT ${SP}`);
    try {
      await dbClient.query(
        `INSERT INTO event_audit_log
           (poolhall_id, event_type, event_id, action, performed_by_user_id, performed_by_role, snapshot, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [poolhallId, eventType, eventId, action, performedByUserId, performedByRole,
         snapshot ? JSON.stringify(snapshot) : null, detail ? JSON.stringify(detail) : null]
      );
      if (inTransaction) await dbClient.query(`RELEASE SAVEPOINT ${SP}`);
    } catch (insertErr) {
      if (inTransaction) {
        // Unwind just the audit write so the caller's transaction is usable again.
        try {
          await dbClient.query(`ROLLBACK TO SAVEPOINT ${SP}`);
          await dbClient.query(`RELEASE SAVEPOINT ${SP}`);
        } catch (spErr) {
          console.error('[event_audit_log] SAVEPOINT unwind failed:', spErr.message);
        }
      }
      throw insertErr;
    }
  } catch (err) {
    console.error(`[event_audit_log] insert failed (${eventType}/${action}):`, err.message);
  }
}

module.exports = { logEventAudit };
