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
         m.photo_url AS last_photo_url,
         m.audio_url AS last_audio_url,
         m.deleted_for_everyone AS last_deleted_for_everyone,
         m.sent_at AS last_sent_at,
         m.sender_id,
         (SELECT COUNT(*) FROM messages
          WHERE receiver_id = $1 AND sender_id = other_user_id AND read_at IS NULL
          AND deleted_for_receiver = false AND deleted_for_everyone = false) AS unread_count
       FROM (
         SELECT
           CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS other_user_id,
           content, photo_url, audio_url, deleted_for_everyone, sent_at, sender_id,
           deleted_for_sender, deleted_for_receiver
         FROM messages
         WHERE (sender_id = $1 AND deleted_for_sender = false) OR (receiver_id = $1 AND deleted_for_receiver = false)
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
      `SELECT id, sender_id, receiver_id, content, photo_url, audio_url, audio_duration,
              deleted_for_everyone, sent_at, read_at
       FROM messages
       WHERE ((sender_id = $1 AND receiver_id = $2 AND deleted_for_sender = false)
          OR (sender_id = $2 AND receiver_id = $1 AND deleted_for_receiver = false))
       ORDER BY sent_at ASC`,
      [req.userId, req.params.otherUserId]
    );

    await pool.query(
      `UPDATE messages SET read_at = NOW() WHERE sender_id = $1 AND receiver_id = $2 AND read_at IS NULL`,
      [req.params.otherUserId, req.userId]
    );

    const blockCheck = await pool.query(
      `SELECT
        EXISTS(SELECT 1 FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2) AS i_blocked_them,
        EXISTS(SELECT 1 FROM blocked_users WHERE blocker_id = $2 AND blocked_id = $1) AS they_blocked_me`,
      [req.userId, req.params.otherUserId]
    );

    res.json({
      messages: result.rows,
      i_blocked_them: blockCheck.rows[0].i_blocked_them,
      they_blocked_me: blockCheck.rows[0].they_blocked_me,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load messages.' });
  }
});

// POST - send a message (text, and/or a photo, and/or a voice note)
router.post('/', requireAuth, async (req, res) => {
  const { receiver_id, content, photo_url, audio_url, audio_duration, service_id } = req.body;

  if (!receiver_id) {
    return res.status(400).json({ error: 'Receiver is required.' });
  }

  if (!content && !photo_url && !audio_url) {
    return res.status(400).json({ error: 'A message, photo, or voice note is required.' });
  }

  try {
    const blockCheck = await pool.query(
      `SELECT 1 FROM blocked_users WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)`,
      [req.userId, receiver_id]
    );

    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ error: 'You cannot message this user.' });
    }

    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, service_id, content, photo_url, audio_url, audio_duration)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.userId, receiver_id, service_id || null, content || null, photo_url || null, audio_url || null, audio_duration || null]
    );

    const senderResult = await pool.query('SELECT name FROM users WHERE id = $1', [req.userId]);
    const senderName = senderResult.rows[0]?.name || 'Someone';

    let previewText = content;
    if (photo_url) previewText = '📷 Sent a photo';
    if (audio_url) previewText = '🎤 Sent a voice note';

    sendPushNotification(
      receiver_id,
      `New message from ${senderName}`,
      previewText && previewText.length > 60 ? previewText.slice(0, 60) + '...' : previewText,
      { type: 'chat', otherUserId: req.userId }
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not send message.' });
  }
});

// PUT - delete a message just for me
router.put('/:id/delete-for-me', requireAuth, async (req, res) => {
  try {
    const check = await pool.query('SELECT sender_id, receiver_id FROM messages WHERE id = $1', [req.params.id]);

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found.' });
    }

    const msg = check.rows[0];

    if (msg.sender_id === req.userId) {
      await pool.query('UPDATE messages SET deleted_for_sender = true WHERE id = $1', [req.params.id]);
    } else if (msg.receiver_id === req.userId) {
      await pool.query('UPDATE messages SET deleted_for_receiver = true WHERE id = $1', [req.params.id]);
    } else {
      return res.status(403).json({ error: 'You are not part of this conversation.' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete message.' });
  }
});

// PUT - unsend a message for everyone
router.put('/:id/delete-for-everyone', requireAuth, async (req, res) => {
  try {
    const check = await pool.query('SELECT sender_id, read_at FROM messages WHERE id = $1', [req.params.id]);

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found.' });
    }

    const msg = check.rows[0];

    if (msg.sender_id !== req.userId) {
      return res.status(403).json({ error: 'You can only unsend your own messages.' });
    }

    if (msg.read_at) {
      return res.status(400).json({ error: 'This message has already been read and can no longer be unsent for everyone.' });
    }

    await pool.query(
      `UPDATE messages SET deleted_for_everyone = true, content = NULL, photo_url = NULL, audio_url = NULL WHERE id = $1`,
      [req.params.id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not unsend message.' });
  }
});

// GET - unread count
router.get('/unread-count', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*) AS count FROM messages
       WHERE receiver_id = $1 AND read_at IS NULL AND deleted_for_receiver = false AND deleted_for_everyone = false`,
      [req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load unread count.' });
  }
});

// POST - block a user
router.post('/block/:userId', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO blocked_users (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.userId, req.params.userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not block user.' });
  }
});

// DELETE - unblock a user
router.delete('/block/:userId', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2', [req.userId, req.params.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not unblock user.' });
  }
});

module.exports = router;
