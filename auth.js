const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const africastalking = require('africastalking');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');

const JWT_SECRET = process.env.JWT_SECRET;

const AT = africastalking({
  apiKey: process.env.AT_API_KEY,
  username: process.env.AT_USERNAME,
});
const smsService = AT.SMS;

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function toIntlPhone(phone) {
  return phone.startsWith('0') ? '+260' + phone.slice(1) : phone;
}

async function checkOtpLimit(userId) {
  const result = await pool.query(
    'SELECT otp_send_count, otp_window_start FROM users WHERE id = $1',
    [userId]
  );
  const user = result.rows[0];
  const now = new Date();

  const windowStart = user.otp_window_start ? new Date(user.otp_window_start) : null;
  const windowExpired = !windowStart || (now.getTime() - windowStart.getTime()) > 24 * 60 * 60 * 1000;

  if (windowExpired) {
    await pool.query('UPDATE users SET otp_send_count = 1, otp_window_start = NOW() WHERE id = $1', [userId]);
    return { allowed: true };
  }

  if (user.otp_send_count >= 2) {
    const hoursLeft = Math.ceil((24 * 60 * 60 * 1000 - (now.getTime() - windowStart.getTime())) / (60 * 60 * 1000));
    return { allowed: false, hoursLeft };
  }

  await pool.query('UPDATE users SET otp_send_count = otp_send_count + 1 WHERE id = $1', [userId]);
  return { allowed: true };
}

// SIGNUP - name, phone, password only. Everyone starts as a regular customer.
router.post('/signup', async (req, res) => {
  const { name, phone, password, confirmPassword } = req.body;

  if (!name || !phone || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  try {
    const existing = await pool.query('SELECT id, phone_verified FROM users WHERE phone = $1', [phone]);

    const password_hash = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    let user;

    if (existing.rows.length > 0) {
      if (existing.rows[0].phone_verified) {
        return res.status(400).json({ error: 'This phone number is already registered.' });
      }

      const limitCheck = await checkOtpLimit(existing.rows[0].id);
      if (!limitCheck.allowed) {
        return res.status(429).json({ error: `You've reached the code limit. Please try again in ${limitCheck.hoursLeft} hour(s).` });
      }

      const updateResult = await pool.query(
        `UPDATE users SET name = $1, password_hash = $2, otp_code = $3, otp_expires = $4 WHERE phone = $5 RETURNING id, name, phone`,
        [name, password_hash, otp, expires, phone]
      );
      user = updateResult.rows[0];
    } else {
      const insertResult = await pool.query(
        `INSERT INTO users (name, phone, password_hash, otp_code, otp_expires, otp_send_count, otp_window_start)
         VALUES ($1, $2, $3, $4, $5, 1, NOW()) RETURNING id, name, phone`,
        [name, phone, password_hash, otp, expires]
      );
      user = insertResult.rows[0];
    }

    try {
      await smsService.send({
        to: [toIntlPhone(phone)],
        message: `Your ZedEvents verification code is: ${otp}`,
      });
    } catch (smsErr) {
      console.error('SMS send failed:', smsErr);
    }

    res.status(201).json({ user, message: 'Account created. Please verify with the OTP sent to your phone.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

// VERIFY OTP
router.post('/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone and OTP are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Account not found.' });
    }

    const user = result.rows[0];

    if (user.phone_verified) {
      return res.status(400).json({ error: 'Phone already verified.' });
    }

    if (user.otp_code !== otp) {
      return res.status(400).json({ error: 'Incorrect OTP.' });
    }

    if (new Date() > new Date(user.otp_expires)) {
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    await pool.query('UPDATE users SET phone_verified = true, otp_code = NULL, otp_expires = NULL WHERE id = $1', [user.id]);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: { id: user.id, name: user.name, phone: user.phone, is_admin: user.is_admin, is_vendor: user.is_vendor },
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not verify OTP.' });
  }
});

// RESEND OTP
router.post('/resend-otp', async (req, res) => {
  const { phone } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Account not found.' });
    }

    const user = result.rows[0];

    const limitCheck = await checkOtpLimit(user.id);
    if (!limitCheck.allowed) {
      return res.status(429).json({ error: `You've reached the code limit. Please try again in ${limitCheck.hoursLeft} hour(s).` });
    }

    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query('UPDATE users SET otp_code = $1, otp_expires = $2 WHERE phone = $3', [otp, expires, phone]);

    await smsService.send({
      to: [toIntlPhone(phone)],
      message: `Your ZedEvents verification code is: ${otp}`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not resend OTP.' });
  }
});

// FORGOT PASSWORD
router.post('/forgot-password', async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required.' });
  }

  try {
    const result = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No account found with that phone number.' });
    }

    const userId = result.rows[0].id;

    const limitCheck = await checkOtpLimit(userId);
    if (!limitCheck.allowed) {
      return res.status(429).json({ error: `You've reached the code limit. Please try again in ${limitCheck.hoursLeft} hour(s).` });
    }

    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query('UPDATE users SET otp_code = $1, otp_expires = $2 WHERE phone = $3', [otp, expires, phone]);

    await smsService.send({
      to: [toIntlPhone(phone)],
      message: `Your ZedEvents password reset code is: ${otp}`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not send reset code.' });
  }
});

// RESET PASSWORD
router.post('/reset-password', async (req, res) => {
  const { phone, otp, newPassword, confirmNewPassword } = req.body;

  if (!phone || !otp || !newPassword || !confirmNewPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Account not found.' });
    }

    const user = result.rows[0];

    if (user.otp_code !== otp) {
      return res.status(400).json({ error: 'Incorrect code.' });
    }

    if (new Date() > new Date(user.otp_expires)) {
      return res.status(400).json({ error: 'Code has expired. Please request a new one.' });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);

    await pool.query('UPDATE users SET password_hash = $1, otp_code = NULL, otp_expires = NULL WHERE id = $2', [password_hash, user.id]);

    res.json({ success: true, message: 'Password reset successfully. Please log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reset password.' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ error: 'Phone and password are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Phone number or password is incorrect.' });
    }

    const user = result.rows[0];

    if (user.is_deleted) {
      return res.status(400).json({ error: 'Phone number or password is incorrect.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ error: 'Phone number or password is incorrect.' });
    }

    if (user.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });
    }

    if (!user.phone_verified) {
      return res.status(403).json({ error: 'Please verify your phone number first.', needsVerification: true });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: { id: user.id, name: user.name, phone: user.phone, is_admin: user.is_admin, is_vendor: user.is_vendor },
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong logging in.' });
  }
});

// GET - basic public info about a user, for showing in a chat header
router.get('/user-info/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, is_vendor, business_name, business_photo_url, is_admin FROM users WHERE id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      display_name: user.business_name || user.name,
      business_photo_url: user.business_photo_url || null,
      phone: user.phone,
      is_vendor: user.is_vendor,
      is_admin: user.is_admin,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load user info.' });
  }
});

// POST - become a vendor
router.post('/become-vendor', requireAuth, async (req, res) => {
  const { business_name, business_bio, business_photo_url } = req.body;

  if (!business_name || !business_name.trim()) {
    return res.status(400).json({ error: 'Business name is required.' });
  }

  try {
    await pool.query(
      `UPDATE users SET is_vendor = true, business_name = $1, business_bio = $2, business_photo_url = $3 WHERE id = $4`,
      [business_name.trim(), business_bio || null, business_photo_url || null, req.userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not set up your vendor profile.' });
  }
});

// GET - my vendor profile
router.get('/vendor-profile', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT is_vendor, business_name, business_bio, business_photo_url FROM users WHERE id = $1',
      [req.userId]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load vendor profile.' });
  }
});

// PUT - update vendor profile
router.put('/vendor-profile', requireAuth, async (req, res) => {
  const { business_name, business_bio, business_photo_url } = req.body;

  try {
    if (business_name !== undefined) {
      await pool.query('UPDATE users SET business_name = $1 WHERE id = $2', [business_name, req.userId]);
    }
    if (business_bio !== undefined) {
      await pool.query('UPDATE users SET business_bio = $1 WHERE id = $2', [business_bio, req.userId]);
    }
    if (business_photo_url !== undefined) {
      await pool.query('UPDATE users SET business_photo_url = $1 WHERE id = $2', [business_photo_url, req.userId]);
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update vendor profile.' });
  }
});

// DELETE MY ACCOUNT
router.delete('/me', requireAuth, async (req, res) => {
  try {
    const anonymizedPhone = `deleted_${req.userId}_${Date.now()}`;

    await pool.query(
      `UPDATE users SET name = 'Deleted User', phone = $1, password_hash = 'DELETED', push_token = NULL, is_deleted = true, deleted_at = NOW() WHERE id = $2`,
      [anonymizedPhone, req.userId]
    );

    await pool.query(`UPDATE services SET status = 'removed' WHERE vendor_id = $1`, [req.userId]);

    res.json({ success: true, message: 'Your account has been deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete account.' });
  }
});

module.exports = router;
