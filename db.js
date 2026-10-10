// db.js — the shared PostgreSQL pool (moved out of server.js, 2026-10-10).
// One Pool for the whole API: every module requires this file and gets the same instance.
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

module.exports = pool;
