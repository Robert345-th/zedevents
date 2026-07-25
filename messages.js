const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');
const { sendPushNotification } = require('./notifications');

// GET - list of conversations
router.get('/conversations', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT ON (other_user_id)
         other_user_id,
         u.name AS other_user_name,
         m.content AS last_message,
         m.sent_at AS last_sent_at,
         m.sender_id,
         (SELECT COUNT(*) FROM messages
          WHERE receiver_id = $1 AND sender_id = other_user_id AND read_at IS NULL) AS unread_count
       FROM (
         SELECT
           CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS other_user_id,
           content, sent_at, sender_id
         FROM messages
         WHERE sender_id = $1 OR receiver_id = $1
         ORDER BY sent_at DESC
       ) m
       JOIN users u ON u.id = m.other_user_id
       ORDER BY other_user_id, m.sent_at DESC`,
      [req.userId]
    );

    result.rows.sort((a, b) => new Date(b.last_sent_at).getTime() - new Date(a.last_sent_at).getTime());
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load conversations.' });
  }
});

// GET - messages between me and another user
router.get('/conversation/:otherUserId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, content, sent_at, read_at
       FROM messages
       WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
       ORDER BY sent_at ASC`,
      [req.userId, req.params.otherUserId]
    );

    await pool.query(
      `UPDATE messages SET read_at = NOW() WHERE sender_id = $1 AND receiver_id = $2 AND read_at IS NULL`,
      [req.params.otherUserId, req.userId]
    );

    res.json({ messages: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load messages.' });
  }
});

// POST - send a message
router.post('/', requireAuth, async (req, res) => {
  const { receiver_id, content, service_id } = req.body;

  if (!receiver_id || !content) {
    return res.status(400).json({ error: 'Receiver and message content are required.' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, service_id, content) VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.userId, receiver_id, service_id || null, content]
    );

    const senderResult = await pool.query('SELECT name FROM users WHERE id = $1', [req.userId]);
    const senderName = senderResult.rows[0]?.name || 'Someone';

    sendPushNotification(
      receiver_id,
      `New message from ${senderName}`,
      content.length > 60 ? content.slice(0, 60) + '...' : content,
      { type: 'chat', otherUserId: req.userId }
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not send message.' });
  }
});

// GET - unread count
router.get('/unread-count', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) AS count FROM messages WHERE receiver_id = $1 AND read_at IS NULL',
      [req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load unread count.' });
  }
});

module.exports = router;
