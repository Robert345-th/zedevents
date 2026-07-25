const jwt = require('jsonwebtoken');
const pool = require('./db');

async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Not logged in.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const result = await pool.query(
      'SELECT is_suspended, is_deleted FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Account not found. Please log in again.' });
    }

    const account = result.rows[0];

    if (account.is_deleted) {
      return res.status(403).json({ error: 'This account no longer exists.' });
    }

    if (account.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended. Contact support.', suspended: true });
    }

    req.userId = decoded.userId;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired login. Please log in again.' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Could not verify your session.' });
  }
}

module.exports = requireAuth;
