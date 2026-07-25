const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');
const fetch = require('node-fetch');

router.post('/save-token', requireAuth, async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token is required.' });
  }

  try {
    await pool.query('UPDATE users SET push_token = $1 WHERE id = $2', [token, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save push token.' });
  }
});

async function sendPushNotification(userId, title, body, data = {}) {
  try {
    const result = await pool.query('SELECT push_token FROM users WHERE id = $1', [userId]);
    const token = result.rows[0]?.push_token;
    if (!token) return;

    await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: token, sound: 'default', title, body, data }),
    });
  } catch (err) {
    console.error('Push notification failed:', err);
  }
}

module.exports = { router, sendPushNotification };
