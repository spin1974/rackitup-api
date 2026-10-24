// routes/digitalpool.js — read-only proxy for DigitalPool.com public tournament data.
//
// Why this exists: DigitalPool's GraphQL endpoint (https://proxy.digitalpool.com/graphql)
// answers anonymous public reads, but its CORS header only allows Origin
// https://digitalpool.com — so a browser page served from anywhere else (a hall TV
// board, rackit-up.com, or a local file) is blocked from calling it directly.
// Server-to-server has no CORS, so this route fetches on the board's behalf and
// returns the JSON with Access-Control-Allow-Origin: * (safe — it's public,
// read-only, no credentials). It also caches briefly so N televisions pointed at
// the same tournament only cost one upstream call per TTL window.
//
// This is the SAME public query the digitalpool.com bracket page itself fires
// (operationName GetPublicTournamentBracket), replayed verbatim. We only read
// tournaments that are already public; nothing here authenticates or writes.
//
// Mounted from server.js with:  app.use(require('./routes/digitalpool'));

const express = require('express');
const router  = express.Router();

const UPSTREAM     = 'https://proxy.digitalpool.com/graphql';
const CACHE_TTL_MS = 30 * 1000;        // serve a cached copy for 30s
const STALE_MAX_MS = 5 * 60 * 1000;    // if upstream is down, serve stale up to 5 min
const UPSTREAM_TIMEOUT_MS = 10 * 1000;

// The exact public query the digitalpool.com bracket view uses. Replayed as-is so
// Hasura's anonymous-role field permissions are guaranteed to accept it.
const BRACKET_QUERY = `query GetPublicTournamentBracket($tournamentId: Int!) {
  tournament_brackets(
    where: {tournament_id: {_eq: $tournamentId}}
    order_by: {match_number: asc}
  ) {
    id tournament_id hash_id round group group_name identifier place
    challenger1 { id name country skill_level apa_skill_level race_to place seed user_id fargo_id team { id name combined_skill_level __typename } __typename }
    challenger2 { id name country skill_level apa_skill_level race_to place seed user_id fargo_id team { id name combined_skill_level __typename } __typename }
    tournament_match_sets(order_by: {number: asc}) { id number challenger1_id challenger1_score challenger1_race_to challenger1_is_winner challenger1_is_forfeit challenger1_is_withdraw challenger2_id challenger2_score challenger2_race_to challenger2_is_winner challenger2_is_forfeit challenger2_is_withdraw status __typename }
    challenger1_id challenger1_name challenger1_country challenger1_skill_level challenger1_score challenger1_points challenger1_race_to challenger1_seed challenger1_is_winner challenger1_is_forfeit challenger1_is_withdraw
    challenger2_id challenger2_name challenger2_country challenger2_skill_level challenger2_score challenger2_points challenger2_race_to challenger2_seed challenger2_is_winner challenger2_is_forfeit challenger2_is_withdraw
    match_number match_id match_color table_id table_name scheduled_table_id priority
    scheduled_table { label __typename }
    scheduled_time start_time end_time duration status progress
    loser_from loser_from_num loser_to loser_to_num winner_from winner_to winner_to_num
    winner_from_top_num winner_from_bottom_num loser_from_top_num loser_from_bottom_num
    advance_to stage_id stage_number is_bye is_split shootout_winner challenger1_shootout challenger2_shootout
    is_semi_finals is_finals is_consolidation_finals
    livestream_url livestream_cameras livestream_thumbnail match_custom_text match_custom_link
    called_at on_clock_player_id on_clock_end_time
    pool_table { id slug label status is_streaming_table livestream_url livestream_cameras __typename }
    __typename
  }
}`;

// tournamentId -> { at: epochMs, payload: {...} }
const cache = new Map();

async function fetchBracket(tournamentId) {
  const res = await fetch(UPSTREAM, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // Mimic the real client so the upstream proxy treats us like the site.
      'origin': 'https://digitalpool.com',
      'x-client-environment': 'prod',
      'user-agent': 'RackItUp-DigitalPool-Board/1.0 (+https://rackit-up.com)'
    },
    body: JSON.stringify({
      operationName: 'GetPublicTournamentBracket',
      variables: { tournamentId },
      query: BRACKET_QUERY
    }),
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
  });

  if (!res.ok) {
    const e = new Error(`Upstream ${res.status}`);
    e.status = 502;
    throw e;
  }
  const json = await res.json();
  if (json.errors) {
    const e = new Error('Upstream GraphQL error: ' + JSON.stringify(json.errors).slice(0, 300));
    e.status = 502;
    throw e;
  }
  const matches = (json.data && json.data.tournament_brackets) || [];
  return { fetchedAt: new Date().toISOString(), tournament_id: tournamentId, tournament_brackets: matches };
}

// GET /public/digitalpool/bracket?tournamentId=168134
// No auth. Returns { fetchedAt, cached, stale, tournament_id, tournament_brackets: [...] }.
router.get('/public/digitalpool/bracket', async (req, res) => {
  // Public, read-only, no credentials — safe to allow any origin so the board can
  // be opened from rackit-up.com OR as a plain local file on the hall computer.
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'no-store');

  const tournamentId = parseInt(req.query.tournamentId, 10);
  if (!Number.isInteger(tournamentId) || tournamentId <= 0) {
    return res.status(400).json({ error: 'tournamentId must be a positive integer' });
  }

  const now = Date.now();
  const hit = cache.get(tournamentId);
  if (hit && now - hit.at < CACHE_TTL_MS) {
    return res.json({ ...hit.payload, cached: true, stale: false });
  }

  try {
    const payload = await fetchBracket(tournamentId);
    cache.set(tournamentId, { at: now, payload });
    return res.json({ ...payload, cached: false, stale: false });
  } catch (err) {
    // Upstream failed — serve a recent cached copy rather than going blank on the TV.
    if (hit && now - hit.at < STALE_MAX_MS) {
      return res.json({ ...hit.payload, cached: true, stale: true });
    }
    return res.status(err.status || 502).json({ error: err.message || 'Upstream fetch failed' });
  }
});

// Preflight (harmless; the board uses a simple GET so this normally isn't hit).
router.options('/public/digitalpool/bracket', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.sendStatus(204);
});

module.exports = router;
