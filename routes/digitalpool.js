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

// Lean metadata query, by tournament id. Enough for the board header (name + venue).
// Separate, optional call — if it fails the bracket still renders and the board
// falls back to "Tournament #id", so a metadata hiccup never breaks the board.
const META_QUERY = `query DpTournamentMeta($tournamentId: Int!) {
  tournaments(where: {id: {_eq: $tournamentId}}) {
    id name slug status progress tournament_type game_type
    venue { name city region country __typename }
    __typename
  }
}`;

const UPSTREAM_HEADERS = {
  'content-type': 'application/json',
  'origin': 'https://digitalpool.com',
  'x-client-environment': 'prod',
  'user-agent': 'RackItUp-DigitalPool-Board/1.0 (+https://rackit-up.com)'
};

async function gql(operationName, variables, query) {
  const res = await fetch(UPSTREAM, {
    method: 'POST',
    headers: UPSTREAM_HEADERS,
    body: JSON.stringify({ operationName, variables, query }),
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
  });
  if (!res.ok) { const e = new Error('Upstream ' + res.status); e.status = 502; throw e; }
  const json = await res.json();
  if (json.errors) { const e = new Error('Upstream GraphQL error: ' + JSON.stringify(json.errors).slice(0, 300)); e.status = 502; throw e; }
  return json.data || {};
}

// Build the board's header subtitle from the match rows + (optional) venue.
function buildSubtitle(matches, venue) {
  const players = new Set();
  let hasLosers = false;
  for (const m of matches) {
    if (m.round < 0) hasLosers = true;
    for (const side of ['challenger1', 'challenger2']) {
      const id = m[side + '_id'], name = m[side + '_name'];
      if (id && name && name !== 'BYE') players.add(id);
    }
  }
  const bits = [];
  if (venue) {
    const where = [venue.name, venue.city].filter(Boolean).join(', ');
    if (where) bits.push(where);
  }
  bits.push(players.size + ' players');
  bits.push((hasLosers ? 'double' : 'single') + ' elimination');
  return bits.join(' · ');
}

async function fetchBracket(tournamentId) {
  // Bracket is required; metadata is best-effort (name/venue for the header).
  const [bracketData, metaData] = await Promise.all([
    gql('GetPublicTournamentBracket', { tournamentId }, BRACKET_QUERY),
    gql('DpTournamentMeta', { tournamentId }, META_QUERY).catch(() => null)
  ]);

  const matches = bracketData.tournament_brackets || [];
  const meta = metaData && metaData.tournaments && metaData.tournaments[0];

  const payload = {
    fetchedAt: new Date().toISOString(),
    tournament_id: tournamentId,
    tournament_brackets: matches
  };
  if (meta) {
    payload.tournament_name = meta.name;
    payload.tournament_slug = meta.slug;
    payload.tournament_sub  = buildSubtitle(matches, meta.venue);
  }
  return payload;
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

// ── Tournament search ─────────────────────────────────────────────────────────
// Replays digitalpool.com's own SearchTournaments3WithStatus query verbatim (so it
// keeps working even if the upstream whitelists query strings). Matches on
// tournament name OR venue name/city/region, public tournaments only. Status
// defaults to IN_PROGRESS — the live-event case a hall TV wants — and is
// overridable via ?status=IN_PROGRESS,COMPLETED (values are DigitalPool's own
// tournament_status_enum; unknown values would be rejected upstream).
const SEARCH_QUERY = `query SearchTournaments3WithStatus($name: String = "%%", $limit: Int = 10, $offset: Int = 0, $game_type: String = "%", $status: [tournament_status_enum!]) {
  tournaments_aggregate(where: {_and: [{is_public: {_eq: true}}, {game_type: {_ilike: $game_type}}, {status: {_in: $status}}, {_or: [{name: {_ilike: $name}}, {venue: {name: {_ilike: $name}}}, {venue: {city: {_ilike: $name}}}, {venue: {region: {_ilike: $name}}}]}]}) {
    aggregate { count __typename } __typename
  }
  tournaments(where: {_and: [{is_public: {_eq: true}}, {game_type: {_ilike: $game_type}}, {status: {_in: $status}}, {_or: [{name: {_ilike: $name}}, {venue: {name: {_ilike: $name}}}, {venue: {city: {_ilike: $name}}}, {venue: {region: {_ilike: $name}}}]}]}, limit: $limit, offset: $offset, order_by: [{is_featured: desc_nulls_last}, {start_date_time: desc}]) {
    id name slug status progress start_date_time flyer game_type tournament_type tournament_format
    winners_race_to losers_race_to is_featured is_public
    tournament_players_aggregate { aggregate { count __typename } __typename }
    tournament_brackets_aggregate { aggregate { count __typename } __typename }
    venue { id name slug city country region __typename }
    __typename
  }
}`;

const searchCache = new Map(); // key -> { at, payload }

router.get('/public/digitalpool/search', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'no-store');

  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.status(400).json({ error: 'q must be at least 2 characters' });

  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 50);
  const status = String(req.query.status || 'IN_PROGRESS')
    .split(',').map(s => s.trim()).filter(Boolean);
  const name = '%' + q + '%';

  const key = status.join(',') + '|' + limit + '|' + name.toLowerCase();
  const now = Date.now();
  const hit = searchCache.get(key);
  if (hit && now - hit.at < 15000) return res.json({ ...hit.payload, cached: true });

  try {
    const r = await fetch(UPSTREAM, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'https://digitalpool.com',
        'x-client-environment': 'prod',
        'user-agent': 'RackItUp-DigitalPool-Board/1.0 (+https://rackit-up.com)'
      },
      body: JSON.stringify({
        operationName: 'SearchTournaments3WithStatus',
        variables: { name, limit, offset: 0, game_type: '%', status },
        query: SEARCH_QUERY
      }),
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
    });
    if (!r.ok) { const e = new Error('Upstream ' + r.status); e.status = 502; throw e; }
    const json = await r.json();
    if (json.errors) { const e = new Error('Upstream GraphQL error: ' + JSON.stringify(json.errors).slice(0, 300)); e.status = 502; throw e; }
    const data = json.data || {};
    const payload = {
      fetchedAt: new Date().toISOString(),
      q,
      count: (data.tournaments_aggregate && data.tournaments_aggregate.aggregate && data.tournaments_aggregate.aggregate.count) || 0,
      tournaments: data.tournaments || []
    };
    searchCache.set(key, { at: now, payload });
    return res.json({ ...payload, cached: false });
  } catch (err) {
    return res.status(err.status || 502).json({ error: err.message || 'Upstream search failed' });
  }
});

router.options('/public/digitalpool/search', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.sendStatus(204);
});

module.exports = router;
