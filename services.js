const express = require('express');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');

let locationColumnsReady = false;

async function ensureServiceLocationColumns() {
  if (locationColumnsReady) return;
  await pool.query('ALTER TABLE services ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION');
  await pool.query('ALTER TABLE services ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION');
  await pool.query('ALTER TABLE services ADD COLUMN IF NOT EXISTS location_label TEXT');
  locationColumnsReady = true;
}

const CITY_COORDS = {
  lusaka: { lat: -15.3875, lng: 28.3228 },
  ndola: { lat: -12.9682, lng: 28.6364 },
  kitwe: { lat: -12.8024, lng: 28.2132 },
  kabwe: { lat: -14.4419, lng: 28.4492 },
  livingstone: { lat: -17.8419, lng: 25.8544 },
  chipata: { lat: -13.6333, lng: 32.65 },
  solwezi: { lat: -12.1688, lng: 26.3894 },
  mongu: { lat: -15.2486, lng: 23.1274 },
  kasama: { lat: -10.2129, lng: 31.1917 },
  choma: { lat: -16.8067, lng: 26.985 },
};

function coordsFromCity(city) {
  if (!city) return null;
  const key = String(city).trim().toLowerCase();
  return CITY_COORDS[key] || null;
}

async function resolveServiceLocation(userId, body) {
  const lat = body.latitude != null ? parseFloat(body.latitude) : null;
  const lng = body.longitude != null ? parseFloat(body.longitude) : null;
  if (Number.isFinite(lat) && Number.isFinite(lng)) {
    return {
      latitude: lat,
      longitude: lng,
      location_label: body.location_label?.trim() || null,
    };
  }

  const vendor = await pool.query(
    'SELECT city, shop_location_label, home_location_label FROM users WHERE id = $1',
    [userId]
  );
  const v = vendor.rows[0];
  const coords = coordsFromCity(v?.city);
  return {
    latitude: coords?.lat ?? null,
    longitude: coords?.lng ?? null,
    location_label: body.location_label?.trim() || v?.shop_location_label || v?.home_location_label || v?.city || null,
  };
}

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
    await ensureServiceLocationColumns();
    let query = `
      SELECT s.id, s.title, s.description, s.price, s.photos, s.date_posted, s.vendor_id,
             s.latitude, s.longitude, s.location_label,
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

// GET - single service detail (public only sees approved/active)
router.get('/:id', async (req, res) => {
  try {
    await ensureServiceLocationColumns();
    const result = await pool.query(
      `SELECT s.id, s.title, s.description, s.price, s.photos, s.status, s.date_posted, s.category_id, s.vendor_id,
              s.latitude, s.longitude, s.location_label,
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

    const service = result.rows[0];
    if (service.status !== 'active') {
      let viewerId = null;
      const auth = req.headers.authorization;
      if (auth && auth.startsWith('Bearer ')) {
        try {
          const jwt = require('jsonwebtoken');
          const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
          viewerId = decoded.userId;
        } catch { /* ignore invalid token */ }
      }
      if (Number(viewerId) !== Number(service.vendor_id)) {
        return res.status(404).json({ error: 'Service not found.' });
      }
    }

    res.json(service);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load service.' });
  }
});

// POST - create a new service listing (must be a vendor). Starts pending until admin approves.
router.post('/', requireAuth, async (req, res) => {
  const { title, description, price, category_id, photos, latitude, longitude, location_label } = req.body;

  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'Title is required.' });
  }

  try {
    await ensureServiceLocationColumns();
    const userCheck = await pool.query('SELECT is_vendor, vendor_status FROM users WHERE id = $1', [req.userId]);

    if (!userCheck.rows[0]?.is_vendor) {
      return res.status(403).json({ error: 'You need to set up a vendor profile before posting.', needsVendorProfile: true });
    }

    const vendorStatus = userCheck.rows[0].vendor_status;
    if (vendorStatus === 'pending') {
      return res.status(403).json({ error: 'Your vendor profile is still under review.', vendorStatus: 'pending' });
    }
    if (vendorStatus === 'rejected') {
      return res.status(403).json({ error: 'Your vendor application was not approved.', vendorStatus: 'rejected' });
    }

    const location = await resolveServiceLocation(req.userId, { latitude, longitude, location_label });

    const result = await pool.query(
      `INSERT INTO services (vendor_id, title, description, price, category_id, photos, status, latitude, longitude, location_label)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
       RETURNING *`,
      [
        req.userId,
        title.trim(),
        description || null,
        price || null,
        category_id || null,
        photos || [],
        location.latitude,
        location.longitude,
        location.location_label,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not create service.' });
  }
});

// PUT - edit a service (owner only). Goes back to pending until re-approved.
router.put('/:id', requireAuth, async (req, res) => {
  const { title, description, price, category_id, photos, latitude, longitude, location_label } = req.body;

  try {
    await ensureServiceLocationColumns();
    const check = await pool.query('SELECT vendor_id, status FROM services WHERE id = $1', [req.params.id]);

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found.' });
    }

    if (check.rows[0].vendor_id !== req.userId) {
      return res.status(403).json({ error: 'You can only edit your own services.' });
    }

    if (check.rows[0].status === 'removed') {
      return res.status(400).json({ error: 'This service was removed and cannot be edited.' });
    }

    if (!title || !String(title).trim()) {
      return res.status(400).json({ error: 'Title is required.' });
    }

    const location = await resolveServiceLocation(req.userId, { latitude, longitude, location_label });

    const result = await pool.query(
      `UPDATE services
       SET title = $1, description = $2, price = $3, category_id = $4, photos = $5,
           latitude = COALESCE($6, latitude), longitude = COALESCE($7, longitude),
           location_label = COALESCE($8, location_label), status = 'pending'
       WHERE id = $9
       RETURNING *`,
      [
        String(title).trim(),
        description || null,
        price || null,
        category_id || null,
        photos || [],
        location.latitude,
        location.longitude,
        location.location_label,
        req.params.id,
      ]
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
