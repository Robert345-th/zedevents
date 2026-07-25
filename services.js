const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');

// GET - list of event categories (Catering, DJ & Sound, Tents & Chairs, etc.)
router.get('/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM categories ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load categories.' });
  }
});

// GET - public feed of active services, optional ?category_id= filter
router.get('/', async (req, res) => {
  const { category_id } = req.query;

  try {
    let query = `
      SELECT s.id, s.title, s.description, s.price, s.photos, s.date_posted, s.vendor_id,
             c.name AS category, u.name AS vendor_name, u.business_name, u.business_photo_url
      FROM services s
      LEFT JOIN categories c ON s.category_id = c.id
      LEFT JOIN users u ON s.vendor_id = u.id
      WHERE s.status = 'active'
      AND (u.is_suspended = false OR u.is_suspended IS NULL)
    `;
    const params = [];

    if (category_id) {
      params.push(category_id);
      query += ` AND s.category_id = $${params.length}`;
    }

    query += ' ORDER BY s.date_posted DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load services.' });
  }
});

// GET - my own services
router.get('/mine', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.price, s.photos, s.status, s.date_posted, s.category_id,
              c.name AS category
       FROM services s
       LEFT JOIN categories c ON s.category_id = c.id
       WHERE s.vendor_id = $1
       ORDER BY s.date_posted DESC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load your services.' });
  }
});

// GET - single service detail
router.get('/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.price, s.photos, s.date_posted, s.category_id, s.vendor_id,
              c.name AS category, u.name AS vendor_name, u.phone AS vendor_phone,
              u.business_name, u.business_bio, u.business_photo_url
       FROM services s
       LEFT JOIN categories c ON s.category_id = c.id
       LEFT JOIN users u ON s.vendor_id = u.id
       WHERE s.id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found.' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load service.' });
  }
});

// POST - create a new service listing (must be a vendor). Free for now — no subscription required.
router.post('/', requireAuth, async (req, res) => {
  const { title, description, price, category_id, photos } = req.body;

  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'Title is required.' });
  }

  try {
    const userCheck = await pool.query('SELECT is_vendor FROM users WHERE id = $1', [req.userId]);

    if (!userCheck.rows[0]?.is_vendor) {
      return res.status(403).json({ error: 'You need to set up a vendor profile before posting.', needsVendorProfile: true });
    }

    const result = await pool.query(
      `INSERT INTO services (vendor_id, title, description, price, category_id, photos)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [req.userId, title.trim(), description || null, price || null, category_id || null, photos || []]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not create service.' });
  }
});

// PUT - edit a service (owner only)
router.put('/:id', requireAuth, async (req, res) => {
  const { title, description, price, category_id, photos } = req.body;

  try {
    const check = await pool.query('SELECT vendor_id FROM services WHERE id = $1', [req.params.id]);

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found.' });
    }

    if (check.rows[0].vendor_id !== req.userId) {
      return res.status(403).json({ error: 'You can only edit your own services.' });
    }

    const result = await pool.query(
      `UPDATE services SET title = $1, description = $2, price = $3, category_id = $4, photos = $5 WHERE id = $6 RETURNING *`,
      [title, description, price, category_id, photos || [], req.params.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update service.' });
  }
});

// DELETE - remove a service (owner or admin)
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT vendor_id FROM services WHERE id = $1', [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found.' });
    }

    const adminCheck = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.userId]);
    const isAdmin = adminCheck.rows[0]?.is_admin;
    const isOwner = result.rows[0].vendor_id === req.userId;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ error: 'You can only delete your own services.' });
    }

    await pool.query('DELETE FROM services WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete service.' });
  }
});

// POST - report a service (safety)
router.post('/:id/report', requireAuth, async (req, res) => {
  const { reason } = req.body;

  if (!reason) {
    return res.status(400).json({ error: 'A reason is required.' });
  }

  try {
    await pool.query('INSERT INTO reports (service_id, reason, reported_by) VALUES ($1, $2, $3)', [
      req.params.id,
      reason,
      req.userId,
    ]);
    res.status(201).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not submit report.' });
  }
});

module.exports = router;
