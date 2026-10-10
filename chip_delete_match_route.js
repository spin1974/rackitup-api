// OPTIONAL small API addition for rackitup-api/server.js (commit to main).
// Paste directly AFTER the existing  app.delete('/hall/chip-tournaments/:id/matches/:matchId/result', ...)  route.
//
// Why: correcting a result after the next round has already been drawn means throwing that round's
// (not yet played) matches away. There is no route that deletes a chip_matches row, so today the desktop page's
// rollback leaves those rows behind as 'playing' and a reload brings them back. mobile/chip-tournament.html v0.2.0
// calls this route for that case and carries on if it is missing (it only logs a warning).
// Only a match that is still 'playing' can be deleted; a played match is reversed with .../result instead.
app.delete('/hall/chip-tournaments/:id/matches/:matchId', requireAuth, requireHallAdmin, async (req, res) => {
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
