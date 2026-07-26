const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');

// GET - my favorited services
router.get('/', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.title, s.price, s.photos, s.date_posted,
              c.name AS category, u.business_name, u.name AS vendor_name
       FROM favorites f
       JOIN services s ON f.service_id = s.id
       LEFT JOIN categories c ON s.category_id = c.id
       LEFT JOIN users u ON s.vendor_id = u.id
       WHERE f.user_id = $1 AND s.status = 'active'
       ORDER BY f.id DESC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load favorites.' });
  }
});

// POST - favorite a service
router.post('/:serviceId', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO favorites (user_id, service_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.userId, req.params.serviceId]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not favorite service.' });
  }
});

// DELETE - unfavorite a service
router.delete('/:serviceId', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM favorites WHERE user_id = $1 AND service_id = $2', [req.userId, req.params.serviceId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not unfavorite service.' });
  }
});

module.exports = router;
