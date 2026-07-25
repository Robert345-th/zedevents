const pool = require('./db');

async function requireAdmin(req, res, next) {
  try {
    const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.userId]);

    if (!result.rows[0]?.is_admin) {
      return res.status(403).json({ error: 'Admin access only.' });
    }

    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not verify admin access.' });
  }
}

module.exports = requireAdmin;
