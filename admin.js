const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');
const requireAdmin = require('./requireAdmin');
const { sendPushNotification } = require('./notifications');

// GET - list all users
router.get('/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, is_vendor, is_suspended, date_joined FROM users ORDER BY date_joined DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load users.' });
  }
});

// PUT - suspend a user
router.put('/users/:id/suspend', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_suspended = true WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not suspend user.' });
  }
});

// PUT - unsuspend a user
router.put('/users/:id/unsuspend', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_suspended = false WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not unsuspend user.' });
  }
});

// GET - pending service reports
router.get('/reports/pending', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.id, r.reason, r.date, s.id AS service_id, s.title, u.name AS reporter_name
       FROM reports r
       JOIN services s ON r.service_id = s.id
       JOIN users u ON r.reported_by = u.id
       WHERE r.status = 'pending'
       ORDER BY r.date DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load reports.' });
  }
});

// PUT - dismiss a report
router.put('/reports/:id/dismiss', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query(`UPDATE reports SET status = 'dismissed' WHERE id = $1`, [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not dismiss report.' });
  }
});

// POST - broadcast a message to everyone
router.post('/broadcast', requireAuth, requireAdmin, async (req, res) => {
  const { title, message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'A message is required.' });
  }

  try {
    const allUsersResult = await pool.query('SELECT id, push_token FROM users WHERE id != $1', [req.userId]);

    for (const user of allUsersResult.rows) {
      if (user.push_token) {
        sendPushNotification(user.id, title?.trim() || '📢 ZedEvents', message);
      }
    }

    res.json({ success: true, notified: allUsersResult.rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not send broadcast.' });
  }
});

module.exports = router;
