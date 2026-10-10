// routes/chip.js — every Chip Tournament route (hall admin + public), moved out of server.js on 2026-10-10.
// EXTRACTION ONLY: route bodies are byte-for-byte what was in server.js; the only edit is `app.` -> `router.`
// on each registration line. Registration order is unchanged (hall routes first, then the public ones).
// Mounted from server.js with:  app.use(require('./routes/chip'));
const express = require('express');
const router  = express.Router();

const pool = require('../db');
const { requireAuth, requireHallAuth, requireHallAdmin } = require('../middleware/auth');
const { logEventAudit } = require('../lib/audit');

// ═══════════════════════════════════════════════════════════════════════════════
// CHIP TOURNAMENT ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/hall/chip-tournaments', requireAuth, requireHallAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ct.tournament_id, ct.poolhall_id, ct.name, ct.status, ct.config, ct.fargo_config,
              ct.public_id, ct.created_at, ct.started_at, ct.finished_at,
              COALESCE((SELECT json_agg(json_build_object('id', et.id, 'name', et.name, 'is_active', et.is_active) ORDER BY et.name)
                          FROM chip_event_tags cet JOIN event_tags et ON et.id = cet.tag_id
                         WHERE cet.tournament_id = ct.tournament_id), '[]'::json) AS tags
       FROM chip_tournaments ct WHERE ct.poolhall_id = $1 ORDER BY ct.created_at DESC`,
      [req.hallId]
    );
    res.json({ tournaments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/hall/chip-tournaments', requireAuth, requireHallAdmin, async (req, res) => {
  const { name, config, fargo_config } = req.body;
  if (!config || typeof config !== 'object') return res.status(400).json({ error: 'config object is required' });
  // 2026-10-09: optional tag_ids so tags can be chosen at creation. Validated BEFORE anything is inserted, and the
  // tournament + its tags commit together, so a bad tag id can never leave an untagged tournament behind.
  const tagIds = Array.isArray(req.body.tag_ids) ? [...new Set(req.body.tag_ids.map(n => parseInt(n, 10)))] : [];
  if (tagIds.some(n => !Number.isInteger(n))) return res.status(400).json({ error: 'tag_ids must be integers' });
  const client = await pool.connect();
  try {
    if (tagIds.length > 0) {
      const validTags = await client.query(
        `SELECT id FROM event_tags WHERE poolhall_id = $1 AND id = ANY($2::int[])`, [req.hallId, tagIds]
      );
      if (validTags.rows.length !== tagIds.length) return res.status(400).json({ error: 'One or more tag_ids are invalid for this hall' });
    }
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO chip_tournaments (poolhall_id, name, status, config, fargo_config, created_at)
       VALUES ($1, $2, 'setup', $3, $4, NOW())
       RETURNING tournament_id, poolhall_id, name, status, config, fargo_config, public_id, created_at`,
      [req.hallId, name || null, JSON.stringify(config), fargo_config ? JSON.stringify(fargo_config) : null]
    );
    const tournament = result.rows[0];
    for (const tagId of tagIds) {
      await client.query(`INSERT INTO chip_event_tags (tournament_id, tag_id) VALUES ($1, $2)`, [tournament.tournament_id, tagId]);
    }
    const tagRows = await client.query(
      `SELECT et.id, et.name, et.is_active FROM chip_event_tags cet JOIN event_tags et ON et.id = cet.tag_id
        WHERE cet.tournament_id = $1 ORDER BY et.name ASC`, [tournament.tournament_id]
    );
    await client.query('COMMIT');
    // Event audit log (chip wiring, 2026-10-04) -- same shape as Round Robin's create.
    await logEventAudit(pool, {
      poolhallId: req.hallId, eventType: 'chip_tournament', eventId: tournament.tournament_id,
      action: 'created', req, snapshot: tournament
    });
    res.status(201).json({ tournament, tags: tagRows.rows });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (e) { /* no open transaction */ }
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

router.put('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
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
    // Event audit log (chip wiring, 2026-10-04). Mirrors Round Robin's PUT: only when the status
    // actually changes (a config-only save such as Save Payouts logs nothing), and a transition INTO
    // 'finished' emits 'finished' rather than 'status_change' so completion reads the same across
    // modules. Logged on the transaction client so it commits atomically with the change itself;
    // logEventAudit's SAVEPOINT keeps a rejected audit write from rolling the real work back.
    if (status && status !== row.status) {
      await logEventAudit(client, {
        poolhallId: req.hallId, eventType: 'chip_tournament', eventId: id,
        action: isNewFinish ? 'finished' : 'status_change', req, snapshot: result.rows[0],
        detail: { old_status: row.status, new_status: status }
      });
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

router.delete('/hall/chip-tournaments/:id', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    // Event audit log (chip wiring, 2026-10-04): snapshot the tournament + capture counts and roster
    // BEFORE the delete cascades them away -- the only chance to record what was lost. Same pattern as
    // the Round Robin and Try League deletes. Reset on an unfinished tournament lands here.
    const existing = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status, config, fargo_config, created_at, started_at, finished_at
       FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const snapshot = existing.rows[0];
    const counts = await pool.query(
      `SELECT
         (SELECT COUNT(*) FROM chip_tournament_players WHERE tournament_id = $1) AS player_count,
         (SELECT COUNT(*) FROM chip_matches WHERE tournament_id = $1) AS match_count,
         (SELECT COUNT(*) FROM chip_matches WHERE tournament_id = $1 AND status = 'done') AS matches_done`, [id]
    );
    const roster = await pool.query(
      `SELECT p.first_name, p.last_name
       FROM chip_tournament_players ctp JOIN player p ON p.player_id = ctp.player_id
       WHERE ctp.tournament_id = $1 ORDER BY ctp.id ASC`, [id]
    );
    const result = await pool.query(
      `DELETE FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2
       RETURNING tournament_id, name, status`, [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    await logEventAudit(pool, {
      poolhallId: req.hallId, eventType: 'chip_tournament', eventId: id, action: 'deleted', req,
      snapshot,
      detail: {
        player_count: parseInt(counts.rows[0].player_count, 10),
        match_count:  parseInt(counts.rows[0].match_count, 10),
        matches_done: parseInt(counts.rows[0].matches_done, 10),
        roster: roster.rows.map(r => `${r.first_name} ${r.last_name}`)
      }
    });
    res.json({ message: 'Tournament deleted', tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/hall/chip-tournaments/:id', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT tournament_id, poolhall_id, name, status, config, fargo_config, public_id, created_at, started_at, finished_at
       FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    res.json({ tournament: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Chip Tournament event tags (added 2026-10-09) ───────────────────────────
// Event-scoped, Try League style: a chip tournament is ONE event per night (no groups), so the join
// table is chip_event_tags (tournament_id, tag_id) -- never per-group, never per-player. Uses the shared
// hall-scoped event_tags pool. No status restriction: tags can be set or changed at any point, including
// after Finish (retroactive edit from the Standings view / Historical tab). Not audit-logged.
router.get('/hall/chip-tournaments/:id/tags', requireAuth, requireHallAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const own = await pool.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (own.rows.length === 0) return res.status(404).json({ error: 'Tournament not found' });
    const result = await pool.query(
      `SELECT et.id, et.name, et.is_active
         FROM chip_event_tags cet JOIN event_tags et ON et.id = cet.tag_id
        WHERE cet.tournament_id = $1 ORDER BY et.name ASC`, [id]
    );
    res.json({ tags: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Full replace -- body: { tag_ids: [...] }. Mirrors the Round Robin group version, one level up.
router.put('/hall/chip-tournaments/:id/tags', requireAuth, requireHallAdmin, async (req, res) => {
  const { id } = req.params;
  const tagIds = Array.isArray(req.body.tag_ids) ? req.body.tag_ids.map(n => parseInt(n, 10)) : [];
  if (tagIds.some(n => !Number.isInteger(n))) return res.status(400).json({ error: 'tag_ids must be integers' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const own = await client.query(
      `SELECT tournament_id FROM chip_tournaments WHERE tournament_id = $1 AND poolhall_id = $2`, [id, req.hallId]
    );
    if (own.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Tournament not found' });
    }
    const uniqueIds = [...new Set(tagIds)];
    if (uniqueIds.length > 0) {
      const validTags = await client.query(
        `SELECT id FROM event_tags WHERE poolhall_id = $1 AND id = ANY($2::int[])`, [req.hallId, uniqueIds]
      );
      if (validTags.rows.length !== uniqueIds.length) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'One or more tag_ids are invalid for this hall' });
      }
    }
    await client.query(`DELETE FROM chip_event_tags WHERE tournament_id = $1`, [id]);
    for (const tagId of uniqueIds) {
      await client.query(`INSERT INTO chip_event_tags (tournament_id, tag_id) VALUES ($1, $2)`, [id, tagId]);
    }
    const result = await client.query(
      `SELECT et.id, et.name, et.is_active
         FROM chip_event_tags cet JOIN event_tags et ON et.id = cet.tag_id
        WHERE cet.tournament_id = $1 ORDER BY et.name ASC`, [id]
    );
    await client.query('COMMIT');
    res.json({ tags: result.rows });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ── GET /hall/chip-tag-standings ──────────────────────────────────────────────
// Cross-tournament chip standings for halladmin/standings.html (type=chip). Optional ?tag_ids=1,2 (OR across
// tags, same as the RR/TL routes); no tag_ids = every finished chip tournament at the hall.
// WHY a live query and not chip_player_stats: that table is one lifetime row per player and cannot be
// tag-filtered. This aggregates chip_tournament_players over FINISHED tournaments carrying the tag, counting
// the same players the finish transition counts for lifetime stats (status champion/eliminated).
// Columns: tournaments_played, titles (finish_position 1 -- split winners each count), wins, losses,
// earnings (payout; admin-only, never on the public pages), rebuys (0 until re-buys are persisted -- see
// context_chip_tournament.md). One row per player; a `tags` badge array lists every tag on any in-scope
// tournament the player was in. Ranked titles, then wins, then earnings.
router.get('/hall/chip-tag-standings', requireAuth, requireHallAuth, async (req, res) => {
  let tagIds = [];
  if (req.query.tag_ids) {
    tagIds = String(req.query.tag_ids).split(',').map(s => parseInt(s, 10)).filter(n => !isNaN(n));
  }
  try {
    let tags = [];
    if (tagIds.length) {
      const tagResult = await pool.query(
        `SELECT id, name, is_active FROM event_tags WHERE id = ANY($1::int[]) AND poolhall_id = $2`,
        [tagIds, req.hallId]
      );
      tags = tagResult.rows;
      if (tags.length === 0) return res.status(404).json({ error: 'No matching tags found' });
      tagIds = tags.map(t => t.id);
    }

    const tRes = await pool.query(
      `SELECT ct.tournament_id
         FROM chip_tournaments ct
        WHERE ct.poolhall_id = $1 AND ct.status = 'finished'
          AND ($2::int[] IS NULL OR EXISTS (
                SELECT 1 FROM chip_event_tags cet WHERE cet.tournament_id = ct.tournament_id AND cet.tag_id = ANY($2::int[])))`,
      [req.hallId, tagIds.length ? tagIds : null]
    );
    const tournamentIds = tRes.rows.map(r => r.tournament_id);
    if (tournamentIds.length === 0) return res.json({ tags, tournament_count: 0, players: [] });

    const pRes = await pool.query(
      `SELECT p.player_id, p.first_name, p.last_name, p.hall_rating,
              COUNT(*)::int AS tournaments_played,
              COUNT(*) FILTER (WHERE ctp.finish_position = 1)::int AS titles,
              COALESCE(SUM(ctp.wins), 0)::int   AS wins,
              COALESCE(SUM(ctp.losses), 0)::int AS losses,
              COALESCE(SUM(ctp.rebuys), 0)::int AS rebuys,
              COALESCE(SUM(ctp.payout), 0)::numeric AS earnings
         FROM chip_tournament_players ctp
         JOIN player p ON p.player_id = ctp.player_id
        WHERE ctp.tournament_id = ANY($1::int[]) AND ctp.status IN ('champion', 'eliminated')
        GROUP BY p.player_id, p.first_name, p.last_name, p.hall_rating`,
      [tournamentIds]
    );

    const tagRes = await pool.query(
      `SELECT DISTINCT ctp.player_id, et.id, et.name
         FROM chip_tournament_players ctp
         JOIN chip_event_tags cet ON cet.tournament_id = ctp.tournament_id
         JOIN event_tags et ON et.id = cet.tag_id
        WHERE ctp.tournament_id = ANY($1::int[]) AND ctp.status IN ('champion', 'eliminated')`,
      [tournamentIds]
    );
    const tagsByPlayer = new Map();
    for (const r of tagRes.rows) {
      if (!tagsByPlayer.has(r.player_id)) tagsByPlayer.set(r.player_id, []);
      tagsByPlayer.get(r.player_id).push({ id: r.id, name: r.name });
    }

    const players = pRes.rows.map(r => ({
      player_id: r.player_id,
      first_name: r.first_name || '',
      last_name: r.last_name || '',
      hall_rating: r.hall_rating != null ? Number(r.hall_rating) : null,
      tournaments_played: r.tournaments_played,
      titles: r.titles,
      wins: r.wins,
      losses: r.losses,
      rebuys: r.rebuys,
      earnings: Math.round(Number(r.earnings) * 100) / 100,
      tags: (tagsByPlayer.get(r.player_id) || []).sort((a, b) => a.name.localeCompare(b.name))
    })).sort((a, b) => (b.titles - a.titles) || (b.wins - a.wins) || (b.earnings - a.earnings)
                       || a.last_name.localeCompare(b.last_name));

    // Standard competition ranking on the same keys the sort uses.
    let place = 0;
    players.forEach((p, i) => {
      const prev = players[i - 1];
      const tied = prev && prev.titles === p.titles && prev.wins === p.wins && prev.earnings === p.earnings;
      if (!tied) place = i + 1;
      p.placement = place;
    });
    for (const p of players) p.shared_placement = players.filter(q => q.placement === p.placement).length > 1;

    res.json({ tags, tournament_count: tournamentIds.length, players });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/hall/chip-tournaments/:id/matches', requireAuth, requireHallAuth, async (req, res) => {
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

router.get('/hall/chip-tournaments/:id/players', requireAuth, requireHallAuth, async (req, res) => {
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

router.post('/hall/chip-tournaments/:id/players', requireAuth, requireHallAdmin, async (req, res) => {
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

router.delete('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
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

router.put('/hall/chip-tournaments/:id/players/:playerId', requireAuth, requireHallAdmin, async (req, res) => {
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

router.post('/hall/chip-tournaments/:id/matches', requireAuth, requireHallAdmin, async (req, res) => {
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

router.delete('/hall/chip-tournaments/:id/matches/:matchId/result', requireAuth, requireHallAdmin, async (req, res) => {
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

// 2026-10-10: remove a match that is still in progress (used when a correction rolls back an already-drawn later round).
// A played match is reversed with DELETE …/result instead.
router.delete('/hall/chip-tournaments/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
  const { id, matchId } = req.params;
  try {
    const check = await pool.query(
      `SELECT cm.match_id, cm.status FROM chip_matches cm JOIN chip_tournaments ct ON ct.tournament_id = cm.tournament_id
       WHERE cm.match_id = $1 AND cm.tournament_id = $2 AND ct.poolhall_id = $3`, [matchId, id, req.hallId]
    );
    if (check.rows.length === 0) return res.status(404).json({ error: 'Match not found' });
    if (check.rows[0].status !== 'playing') return res.status(409).json({ error: 'Only a match that is still in progress can be removed' });
    await pool.query(`DELETE FROM chip_matches WHERE match_id = $1 AND tournament_id = $2`, [matchId, id]);
    res.json({ message: 'Match removed' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/hall/chip-tournaments/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
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

// ── GET /public/chip-tournaments/:publicId ───────────────────────────────────
// Chip Tournament public report (reports/chip.html), added 2026-10-06. No auth.
// Looked up by public_id (opaque 12-char token, same pattern as
// roundrobin_tournaments.public_id) — never the sequential tournament_id.
// Only 'running' or 'finished' tournaments are exposed; a 'setup' tournament has
// no draw yet. Read-only; returns raw rows and the page ranks them (same
// ordering the admin page uses: active players by chips then wins, eliminated
// players by finish_position).
//
// Deliberately NOT returned: payout amounts, entry fee/config, fargo_config and
// player contact/rating fields beyond names — a spectator page has no need of
// money or ratings. In a FINISHED tournament, matches still 'playing' were
// voided by Finish (chip_matches.status has no 'void' value); they are reported
// here as status 'void' so the page can show "not played".
router.get('/public/chip-tournaments/:publicId', async (req, res) => {
  const { publicId } = req.params;
  try {
    const tRes = await pool.query(
      `SELECT ct.tournament_id, ct.name, ct.status, ct.created_at, ct.started_at, ct.finished_at,
              ph.poolhall_name
         FROM chip_tournaments ct
         JOIN poolhall ph ON ph.poolhall_id = ct.poolhall_id
        WHERE ct.public_id = $1 AND ct.status IN ('running', 'finished')`,
      [publicId]
    );
    if (tRes.rows.length === 0) {
      return res.status(404).json({ error: 'Tournament not found or not yet started' });
    }
    const t = tRes.rows[0];

    const pRes = await pool.query(
      `SELECT ctp.player_id, ctp.starting_chips, ctp.current_chips, ctp.finish_position,
              ctp.rebuys, ctp.wins, ctp.losses, ctp.status,
              p.first_name, p.last_name
         FROM chip_tournament_players ctp
         JOIN player p ON p.player_id = ctp.player_id
        WHERE ctp.tournament_id = $1
        ORDER BY ctp.id ASC`,
      [t.tournament_id]
    );

    const mRes = await pool.query(
      `SELECT match_id, round_seq, table_number, p1_id, p2_id, winner_id, loser_id, status, finished_at
         FROM chip_matches
        WHERE tournament_id = $1
        ORDER BY match_id ASC`,
      [t.tournament_id]
    );
    const matches = mRes.rows.map(m =>
      (t.status === 'finished' && m.status === 'playing') ? { ...m, status: 'void' } : m
    );

    res.json({
      tournament: {
        name: t.name, status: t.status,
        created_at: t.created_at, started_at: t.started_at, finished_at: t.finished_at
      },
      poolhall_name: t.poolhall_name,
      players: pRes.rows,
      matches
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /public/poolhalls/:publicId/chip-player-stats ─────────────────────────
// Lifetime Chip Tournament stats (reports/chip-players.html), added 2026-10-06.
// No auth; same shape as rr-player-stats / tl-player-stats. Source is
// chip_player_stats (one lifetime row per player, written by the finish
// transition), plus a 'titles' count (finished tournaments won — finish_position
// 1, split winners each count) computed live. Earnings are NOT exposed publicly.
// No tag filtering yet: chip has no event tags, and chip_player_stats cannot be
// tag-filtered anyway (see context_chip_tournament.md section C.3).
router.get('/public/poolhalls/:publicId/chip-player-stats', async (req, res) => {
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
         COALESCE(s.tournaments_played, 0) AS tournaments_played,
         COALESCE(s.total_wins,   0)       AS total_wins,
         COALESCE(s.total_losses, 0)       AS total_losses,
         (SELECT COUNT(*)::int
            FROM chip_tournament_players ctp
            JOIN chip_tournaments ct ON ct.tournament_id = ctp.tournament_id
           WHERE ctp.player_id = p.player_id
             AND ct.poolhall_id = $1
             AND ct.status = 'finished'
             AND ctp.finish_position = 1) AS titles,
         s.last_played_at
       FROM player p
       JOIN chip_player_stats s
         ON s.player_id = p.player_id AND s.poolhall_id = $1
       WHERE p.poolhall_id = $1
         AND p.deleted_at IS NULL
       ORDER BY s.total_wins DESC, p.last_name, p.first_name`,
      [poolhall_id]
    );

    res.json({ poolhall_name, players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /public/poolhalls/:publicId/chip-tag-stats ────────────────────────────
// No auth. Tag-filtered counterpart to chip-player-stats above, for the dropdown on reports/chip-players.html
// (added 2026-10-09 with chip event tags). tag_ids REQUIRED (comma-separated), OR across tags, ACTIVE tags only --
// same rules as rr-tag-stats / tl-tag-stats. Aggregates FINISHED chip tournaments carrying a selected tag, live from
// chip_tournament_players (chip_player_stats can't be tag-filtered); counts the same players the finish-time stats
// upsert counts (status champion/eliminated). Row shape matches chip-player-stats so the page renders both with one
// code path. Earnings are NOT exposed publicly.
router.get('/public/poolhalls/:publicId/chip-tag-stats', async (req, res) => {
  const { publicId } = req.params;
  let tagIds = [];
  if (req.query.tag_ids) {
    tagIds = String(req.query.tag_ids).split(',').map(s => parseInt(s, 10)).filter(n => !isNaN(n));
  }
  if (!tagIds.length) return res.status(400).json({ error: 'tag_ids is required' });
  try {
    const hallResult = await pool.query(
      `SELECT poolhall_id, poolhall_name FROM poolhall WHERE public_id = $1`, [publicId]
    );
    if (hallResult.rows.length === 0) return res.status(404).json({ error: 'Hall not found' });
    const { poolhall_id: poolhallId, poolhall_name } = hallResult.rows[0];

    const tagResult = await pool.query(
      `SELECT id, name FROM event_tags WHERE id = ANY($1::int[]) AND poolhall_id = $2 AND is_active = true`,
      [tagIds, poolhallId]
    );
    const tags = tagResult.rows;
    if (tags.length === 0) return res.status(404).json({ error: 'No matching tags found' });
    tagIds = tags.map(t => t.id);

    const result = await pool.query(
      `SELECT p.player_id, p.first_name, p.last_name,
              COUNT(*)::int AS tournaments_played,
              COUNT(*) FILTER (WHERE ctp.finish_position = 1)::int AS titles,
              COALESCE(SUM(ctp.wins), 0)::int   AS total_wins,
              COALESCE(SUM(ctp.losses), 0)::int AS total_losses
         FROM chip_tournament_players ctp
         JOIN chip_tournaments ct ON ct.tournament_id = ctp.tournament_id
         JOIN player p ON p.player_id = ctp.player_id
        WHERE ct.poolhall_id = $1 AND ct.status = 'finished'
          AND ctp.status IN ('champion', 'eliminated')
          AND p.deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM chip_event_tags cet WHERE cet.tournament_id = ct.tournament_id AND cet.tag_id = ANY($2::int[]))
        GROUP BY p.player_id, p.first_name, p.last_name
        ORDER BY total_wins DESC, p.last_name, p.first_name`,
      [poolhallId, tagIds]
    );
    res.json({ poolhall_name, tags, players: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
