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

// GET - vendor/shop applications waiting for approval
router.get('/vendor-applications/pending', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, business_name, business_photo_url, business_bio,
              date_of_birth, city, province, selling_type,
              shop_address, home_address, shop_location_label, home_location_label,
              date_joined
       FROM users
       WHERE vendor_status = 'pending'
       ORDER BY date_joined ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load vendor applications.' });
  }
});

// PUT - approve a vendor application
router.put('/vendor-applications/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET vendor_status = 'approved' WHERE id = $1 AND vendor_status = 'pending' RETURNING id, name`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending vendor application not found.' });
    }
    sendPushNotification(
      req.params.id,
      'Shop Approved',
      'Your ZedEvents vendor profile has been approved. You can now post services.'
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not approve vendor application.' });
  }
});

// PUT - reject a vendor application
router.put('/vendor-applications/:id/reject', requireAuth, requireAdmin, async (req, res) => {
  const { reason } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET vendor_status = 'rejected' WHERE id = $1 AND vendor_status = 'pending' RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending vendor application not found.' });
    }
    sendPushNotification(
      req.params.id,
      'Shop Application Declined',
      reason?.trim()
        ? `Your vendor application was not approved: ${reason.trim()}`
        : 'Your vendor application could not be approved. Please contact support.'
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reject vendor application.' });
  }
});

// GET - services waiting for approval
router.get('/services/pending', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.price, s.photos, s.status, s.date_posted,
              c.name AS category, u.name AS vendor_name, u.business_name, u.phone AS vendor_phone
       FROM services s
       LEFT JOIN categories c ON s.category_id = c.id
       LEFT JOIN users u ON s.vendor_id = u.id
       WHERE s.status = 'pending'
       ORDER BY s.date_posted ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load pending services.' });
  }
});

// PUT - approve a service (makes it public)
router.put('/services/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE services SET status = 'active' WHERE id = $1 AND status = 'pending' RETURNING *`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending service not found.' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not approve service.' });
  }
});

// PUT - reject a service
router.put('/services/:id/reject', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE services SET status = 'rejected' WHERE id = $1 AND status = 'pending' RETURNING *`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending service not found.' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reject service.' });
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

// GET - pending country/location change requests
router.get('/location-changes/pending', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, phone, country, city, pending_country, pending_city,
              location_change_reason, location_change_status
       FROM users
       WHERE location_change_status = 'pending'
       ORDER BY id ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load location change requests.' });
  }
});

// PUT - approve location change (applies pending country/city; phone must be updated later for new country)
router.put('/location-changes/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET
         country = pending_country,
         province = pending_country,
         city = pending_city,
         pending_country = NULL,
         pending_city = NULL,
         location_change_reason = NULL,
         location_change_status = 'approved'
       WHERE id = $1 AND location_change_status = 'pending'
       RETURNING id, name, country, city`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending location change not found.' });
    }
    sendPushNotification(
      req.params.id,
      'Location updated',
      'Your country/location change was approved. Update your shop phone if needed for the new country.'
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not approve location change.' });
  }
});

// PUT - reject location change
router.put('/location-changes/:id/reject', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET
         pending_country = NULL,
         pending_city = NULL,
         location_change_reason = NULL,
         location_change_status = 'rejected'
       WHERE id = $1 AND location_change_status = 'pending'
       RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending location change not found.' });
    }
    sendPushNotification(
      req.params.id,
      'Location change declined',
      req.body?.reason?.trim()
        ? `Your location change was not approved: ${req.body.reason.trim()}`
        : 'Your location change request was not approved.'
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reject location change.' });
  }
});

module.exports = router;
