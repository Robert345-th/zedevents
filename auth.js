const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const africastalking = require('africastalking');
const router = express.Router();
const pool = require('./db');
const requireAuth = require('./middleware');
const {
  resolveCountry,
  normalizePhoneForCountry,
  isValidPhoneForCountry,
} = require('./countries');

const JWT_SECRET = process.env.JWT_SECRET;

const AT = africastalking({
  apiKey: process.env.AT_API_KEY,
  username: process.env.AT_USERNAME,
});
const smsService = AT.SMS;

let authSchemaReady = false;

async function ensureAuthSchema() {
  if (authSchemaReady) return;
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS date_of_birth DATE');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS city TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS province TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS pending_country TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS pending_city TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS location_change_reason TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS location_change_status TEXT');
  await pool.query(
    'CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON users (LOWER(email)) WHERE email IS NOT NULL'
  );
  try {
    await pool.query('ALTER TABLE users ALTER COLUMN phone DROP NOT NULL');
  } catch (_) {
    /* older rows still have phones; email-only users may use placeholder */
  }
  authSchemaReady = true;
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function normalizeEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
}

function isAtLeast18(dateOfBirth) {
  if (!dateOfBirth) return false;
  const birth = new Date(`${dateOfBirth}T00:00:00`);
  if (Number.isNaN(birth.getTime())) return false;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (birth >= today) return false;
  const minAgeDate = new Date(today);
  minAgeDate.setFullYear(minAgeDate.getFullYear() - 18);
  return birth <= minAgeDate;
}

/** E.164 for SMS. Keeps +country…; maps legacy Zambian 0… → +260… */
function toIntlPhone(phone) {
  const raw = String(phone || '').trim().replace(/[\s-]/g, '');
  if (!raw || raw.startsWith('e_')) return null;
  if (raw.startsWith('+')) return raw;
  if (raw.startsWith('00')) return '+' + raw.slice(2);
  if (raw.startsWith('0') && raw.length >= 9 && raw.length <= 10) {
    return '+260' + raw.slice(1);
  }
  if (/^\d{8,15}$/.test(raw)) return '+' + raw;
  return raw;
}

function canSendSms(phone) {
  return !!toIntlPhone(phone);
}

/** Stable placeholder when DB still requires phone NOT NULL */
function emailPlaceholderPhone(email) {
  const hash = crypto.createHash('sha256').update(normalizeEmail(email)).digest('hex').slice(0, 14);
  return `e_${hash}`;
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    phone: user.phone && String(user.phone).startsWith('e_') ? null : user.phone,
    email: user.email || null,
    country: user.country || null,
    city: user.city || null,
    date_of_birth: user.date_of_birth || null,
    location_change_status: user.location_change_status || null,
    pending_country: user.pending_country || null,
    is_admin: !!user.is_admin,
    is_vendor: !!user.is_vendor,
  };
}

const ADMIN_PHONE = '0978012009';

function normalizeLocalPhone(phone) {
  if (!phone) return '';
  let p = String(phone).trim().replace(/[\s-]/g, '');
  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('260')) p = '0' + p.slice(3);
  return p;
}

/** Normalize any phone to a storage form (prefer E.164 without + for intl, keep 0… for ZM). */
function normalizePhoneInput(raw) {
  let p = String(raw || '').trim().replace(/[\s-]/g, '');
  if (!p) return '';
  if (p.startsWith('e_')) return p;
  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('00')) p = p.slice(2);
  // Zambia local
  if (p.startsWith('260') && p.length === 12) return '0' + p.slice(3);
  if (p.startsWith('0') && p.length >= 9 && p.length <= 10) return p;
  // International without +: store with leading +
  if (/^\d{8,15}$/.test(p)) return '+' + p;
  return p;
}

function isValidPhoneInput(raw) {
  const p = normalizePhoneInput(raw);
  if (!p || p.startsWith('e_')) return false;
  if (/^0(573\d{6}|574\d{6}|75\d{7}|77\d{7}|95\d{7}|97\d{7})$/.test(p)) return true;
  if (/^\+\d{8,15}$/.test(p)) return true;
  return false;
}

function isAdminPhone(phone) {
  return normalizeLocalPhone(phone) === ADMIN_PHONE;
}

async function ensureAdminFlag(user) {
  if (!user || !isAdminPhone(user.phone) || user.is_admin) return user;
  await pool.query('UPDATE users SET is_admin = true WHERE id = $1', [user.id]);
  user.is_admin = true;
  return user;
}

function generateReferralCodeCandidate() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

async function generateUniqueReferralCode() {
  let code;
  let exists = true;
  while (exists) {
    code = generateReferralCodeCandidate();
    const check = await pool.query('SELECT 1 FROM users WHERE referral_code = $1', [code]);
    exists = check.rows.length > 0;
  }
  return code;
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

// SIGNUP WITH EMAIL (Nexus / worldwide — no SMS required)
router.post('/signup-email', async (req, res) => {
  const { name, email, password, confirmPassword, referral_code, country, date_of_birth } = req.body;
  const cleanEmail = normalizeEmail(email);
  const countryInfo = resolveCountry(country);

  if (!name || !cleanEmail || !password || !confirmPassword || !country || !date_of_birth) {
    return res.status(400).json({ error: 'Name, email, password, country, and date of birth are required.' });
  }
  if (!isValidEmail(cleanEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!countryInfo) {
    return res.status(400).json({ error: 'Please select a valid country.' });
  }
  if (!isAtLeast18(date_of_birth)) {
    return res.status(400).json({ error: 'You must be at least 18 years old to join Nexus.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }
  if (String(password).length < 8 || String(password).length > 72) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    await ensureAuthSchema();

    let referrerId = null;
    if (referral_code && referral_code.trim()) {
      const referrerCheck = await pool.query('SELECT id FROM users WHERE referral_code = $1', [
        referral_code.trim().toUpperCase(),
      ]);
      if (referrerCheck.rows.length === 0) {
        return res.status(400).json({ error: 'That referral code was not found.' });
      }
      referrerId = referrerCheck.rows[0].id;
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = $1 AND (is_deleted = false OR is_deleted IS NULL)',
      [cleanEmail]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'This email is already registered. Please log in.' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const newReferralCode = await generateUniqueReferralCode();
    const placeholderPhone = emailPlaceholderPhone(cleanEmail);

    let user;
    try {
      const insertResult = await pool.query(
        `INSERT INTO users (
           name, phone, email, email_verified, phone_verified, password_hash,
           referral_code, referred_by, country, province, date_of_birth
         )
         VALUES ($1, $2, $3, true, true, $4, $5, $6, $7, $7, $8)
         RETURNING id, name, phone, email, country, city, date_of_birth, is_admin, is_vendor,
                   location_change_status, pending_country`,
        [
          name.trim(),
          placeholderPhone,
          cleanEmail,
          password_hash,
          newReferralCode,
          referrerId,
          countryInfo.code,
          date_of_birth,
        ]
      );
      user = insertResult.rows[0];
    } catch (insertErr) {
      console.error('Email signup insert failed:', insertErr);
      throw insertErr;
    }

    await ensureAdminFlag(user);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      user: publicUser(user),
      token,
      message: 'Account created.',
    });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'This email is already registered. Please log in.' });
    }
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

// LOGIN WITH EMAIL (or email field on /login below)
router.post('/login-email', async (req, res) => {
  const cleanEmail = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  if (!cleanEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  if (!isValidEmail(cleanEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    await ensureAuthSchema();
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = $1 AND (is_deleted = false OR is_deleted IS NULL)',
      [cleanEmail]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Email or password is incorrect.' });
    }

    const user = result.rows[0];
    if (user.is_deleted) {
      return res.status(400).json({ error: 'Email or password is incorrect.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ error: 'Email or password is incorrect.' });
    }
    if (user.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });
    }

    if (!user.referral_code) {
      const newCode = await generateUniqueReferralCode();
      await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [newCode, user.id]);
      user.referral_code = newCode;
    }

    await ensureAdminFlag(user);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ user: publicUser(user), token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong logging in.' });
  }
});

// SIGNUP - name, phone, password, and optional referral code (worldwide phones)
router.post('/signup', async (req, res) => {
  const { name, password, confirmPassword, referral_code } = req.body;
  const phone = normalizePhoneInput(req.body?.phone);

  if (!name || !phone || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (!isValidPhoneInput(phone)) {
    return res.status(400).json({ error: 'Please enter a valid phone number with country code (e.g. +260…).' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  try {
    await ensureAuthSchema();

    let referrerId = null;
    if (referral_code && referral_code.trim()) {
      const referrerCheck = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referral_code.trim().toUpperCase()]);
      if (referrerCheck.rows.length === 0) {
        return res.status(400).json({ error: 'That referral code was not found.' });
      }
      referrerId = referrerCheck.rows[0].id;
    }

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
        `UPDATE users SET name = $1, password_hash = $2, otp_code = $3, otp_expires = $4, referred_by = $5 WHERE phone = $6 RETURNING id, name, phone`,
        [name, password_hash, otp, expires, referrerId, phone]
      );
      user = updateResult.rows[0];
    } else {
      const newReferralCode = await generateUniqueReferralCode();
      const insertResult = await pool.query(
        `INSERT INTO users (name, phone, password_hash, otp_code, otp_expires, otp_send_count, otp_window_start, referral_code, referred_by)
         VALUES ($1, $2, $3, $4, $5, 1, NOW(), $6, $7) RETURNING id, name, phone`,
        [name, phone, password_hash, otp, expires, newReferralCode, referrerId]
      );
      user = insertResult.rows[0];
    }

    const intl = toIntlPhone(phone);
    if (intl) {
      try {
        await smsService.send({
          to: [intl],
          message: `Your ZedEvents verification code is: ${otp}`,
        });
      } catch (smsErr) {
        console.error('SMS send failed:', smsErr);
      }
    }

    res.status(201).json({ user, message: 'Account created. Please verify with the OTP sent to your phone.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

// VERIFY OTP
router.post('/verify-otp', async (req, res) => {
  const phone = normalizePhoneInput(req.body?.phone);
  const { otp } = req.body;

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

    await ensureAdminFlag(user);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: publicUser(user),
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not verify OTP.' });
  }
});

// RESEND OTP
router.post('/resend-otp', async (req, res) => {
  const phone = normalizePhoneInput(req.body?.phone);

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

    const intl = toIntlPhone(phone);
    if (intl) {
      await smsService.send({
        to: [intl],
        message: `Your ZedEvents verification code is: ${otp}`,
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not resend OTP.' });
  }
});

// FORGOT PASSWORD
router.post('/forgot-password', async (req, res) => {
  const phone = normalizePhoneInput(req.body?.phone);

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

    const intl = toIntlPhone(phone);
    if (intl) {
      await smsService.send({
        to: [intl],
        message: `Your ZedEvents password reset code is: ${otp}`,
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not send reset code.' });
  }
});

// RESET PASSWORD
router.post('/reset-password', async (req, res) => {
  const phone = normalizePhoneInput(req.body?.phone);
  const { otp, newPassword, confirmNewPassword } = req.body;

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

// LOGIN — phone or email
router.post('/login', async (req, res) => {
  const password = req.body?.password;
  const email = normalizeEmail(req.body?.email);
  const phone = normalizePhoneInput(req.body?.phone);

  if ((!phone && !email) || !password) {
    return res.status(400).json({ error: 'Email or phone, and password, are required.' });
  }

  // Prefer email path when provided
  if (email) {
    req.body.email = email;
    // reuse login-email logic inline
    try {
      await ensureAuthSchema();
      const result = await pool.query(
        'SELECT * FROM users WHERE LOWER(email) = $1 AND (is_deleted = false OR is_deleted IS NULL)',
        [email]
      );
      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'Email or password is incorrect.' });
      }
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(400).json({ error: 'Email or password is incorrect.' });
      }
      if (user.is_suspended) {
        return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });
      }
      if (!user.referral_code) {
        const newCode = await generateUniqueReferralCode();
        await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [newCode, user.id]);
        user.referral_code = newCode;
      }
      await ensureAdminFlag(user);
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
      return res.json({ user: publicUser(user), token });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Something went wrong logging in.' });
    }
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

    if (!user.referral_code) {
      const newCode = await generateUniqueReferralCode();
      await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [newCode, user.id]);
      user.referral_code = newCode;
    }

    await ensureAdminFlag(user);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: publicUser(user),
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong logging in.' });
  }
});

// GET - current user session (refreshes admin flag for configured admin phone)
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, email, country, city, date_of_birth, is_vendor, business_name, business_photo_url, is_admin,
              location_change_status, pending_country, pending_city
       FROM users WHERE id = $1 AND (is_deleted = false OR is_deleted IS NULL)`,
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = await ensureAdminFlag(result.rows[0]);
    res.json({
      ...publicUser(user),
      business_name: user.business_name,
      business_photo_url: user.business_photo_url,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load account.' });
  }
});

// GET MY REFERRAL INFO
router.get('/referral-info', requireAuth, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT referral_code, free_featured_credits FROM users WHERE id = $1', [req.userId]);

    let referralCode = userResult.rows[0]?.referral_code;
    if (!referralCode) {
      referralCode = await generateUniqueReferralCode();
      await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [referralCode, req.userId]);
    }

    const referralsResult = await pool.query('SELECT COUNT(*) FROM users WHERE referred_by = $1', [req.userId]);
    const vendorReferralsResult = await pool.query('SELECT COUNT(*) FROM users WHERE referred_by = $1 AND is_vendor = true', [req.userId]);

    res.json({
      referral_code: referralCode,
      total_referrals: parseInt(referralsResult.rows[0].count),
      vendor_referrals: parseInt(vendorReferralsResult.rows[0].count),
      free_featured_credits: userResult.rows[0]?.free_featured_credits || 0,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load referral info.' });
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

// Ensure shop-registration columns exist.
async function ensureVendorColumns() {
  await ensureAuthSchema();
  const statements = [
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS selling_type TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_address TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS home_address TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS shop_location_label TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS home_location_label TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_status TEXT',
  ];
  for (const sql of statements) {
    await pool.query(sql);
  }
}

// POST - register shop (profile already has name, country, DOB from Nexus signup)
router.post('/register-shop', requireAuth, async (req, res) => {
  const {
    phone,
    city,
    selling_type,
    shop_name,
    shop_address,
    home_address,
    shop_location_label,
    home_location_label,
    location_label,
    business_bio,
    business_photo_url,
  } = req.body;

  try {
    await ensureVendorColumns();

    const profileResult = await pool.query(
      `SELECT id, name, email, country, province, city, date_of_birth, phone, is_vendor, vendor_status
       FROM users WHERE id = $1`,
      [req.userId]
    );
    if (profileResult.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found.' });
    }
    const profile = profileResult.rows[0];
    const countryCode = profile.country || profile.province;
    if (!countryCode || !profile.date_of_birth) {
      return res.status(400).json({
        error: 'Finish your Nexus profile first (country and date of birth are required).',
      });
    }
    if (!isAtLeast18(profile.date_of_birth)) {
      return res.status(400).json({ error: 'You must be at least 18 years old to register a shop.' });
    }

    const normalizedPhone = normalizePhoneForCountry(phone, countryCode);
    if (!normalizedPhone) {
      const c = resolveCountry(countryCode);
      return res.status(400).json({
        error: c
          ? `Enter a valid ${c.name} phone number (+${c.dial}…).`
          : 'Enter a valid phone number for your registered country.',
      });
    }

    // Prevent another account owning this phone
    const phoneTaken = await pool.query(
      `SELECT id FROM users WHERE phone = $1 AND id <> $2 AND (is_deleted = false OR is_deleted IS NULL)`,
      [normalizedPhone, req.userId]
    );
    if (phoneTaken.rows.length > 0) {
      return res.status(400).json({ error: 'That phone number is already used on another account.' });
    }

    if (!city || !String(city).trim()) {
      return res.status(400).json({ error: 'City is required.' });
    }
    if (!['shop', 'home', 'both'].includes(selling_type)) {
      return res.status(400).json({ error: 'Please choose where you sell — shop, home, or both.' });
    }
    if ((selling_type === 'shop' || selling_type === 'both') && (!shop_name || !shop_address)) {
      return res.status(400).json({ error: 'Please enter your shop name and shop address.' });
    }
    if ((selling_type === 'home' || selling_type === 'both') && !home_address) {
      return res.status(400).json({ error: 'Please enter your home area or address.' });
    }

    const businessName =
      (selling_type === 'home' ? null : shop_name) ||
      shop_name ||
      profile.name;

    await pool.query(
      `UPDATE users SET
         phone = $1,
         phone_verified = true,
         is_vendor = true,
         vendor_status = 'pending',
         business_name = $2,
         business_bio = COALESCE($3, business_bio),
         business_photo_url = COALESCE($4, business_photo_url),
         city = $5,
         province = COALESCE(country, province),
         selling_type = $6,
         shop_address = $7,
         home_address = $8,
         shop_location_label = $9,
         home_location_label = $10
       WHERE id = $11`,
      [
        normalizedPhone,
        businessName.trim(),
        business_bio || null,
        business_photo_url || null,
        String(city).trim(),
        selling_type,
        shop_address || null,
        home_address || null,
        shop_location_label || location_label || null,
        home_location_label || null,
        req.userId,
      ]
    );

    const userResult = await pool.query(
      `SELECT id, name, phone, email, country, city, date_of_birth, is_admin, is_vendor,
              location_change_status, pending_country, referred_by
       FROM users WHERE id = $1`,
      [req.userId]
    );
    const user = userResult.rows[0];
    const referredBy = user?.referred_by;
    if (referredBy) {
      await pool.query('UPDATE users SET free_featured_credits = free_featured_credits + 1 WHERE id = $1', [referredBy]);
      await pool.query('UPDATE users SET free_featured_credits = free_featured_credits + 1 WHERE id = $1', [req.userId]);
    }

    res.json({
      success: true,
      message: 'Submitted — your shop registration is under review. You can use the app while you wait.',
      user: {
        ...publicUser(user),
        vendor_status: 'pending',
        business_name: businessName.trim(),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not submit shop registration.' });
  }
});

// POST - request country/location change (requires admin approval; cannot change freely)
router.post('/request-location-change', requireAuth, async (req, res) => {
  const countryInfo = resolveCountry(req.body?.country);
  const city = String(req.body?.city || '').trim();
  const reason = String(req.body?.reason || '').trim().slice(0, 500);

  if (!countryInfo) {
    return res.status(400).json({ error: 'Please choose a valid new country.' });
  }
  if (!city) {
    return res.status(400).json({ error: 'Please enter your new city.' });
  }
  if (!reason || reason.length < 8) {
    return res.status(400).json({ error: 'Please explain why you moved (at least a short reason).' });
  }

  try {
    await ensureAuthSchema();
    const current = await pool.query(
      'SELECT country, city, location_change_status FROM users WHERE id = $1',
      [req.userId]
    );
    if (current.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found.' });
    }
    if (current.rows[0].location_change_status === 'pending') {
      return res.status(400).json({ error: 'You already have a location change waiting for approval.' });
    }
    if (current.rows[0].country === countryInfo.code && (current.rows[0].city || '') === city) {
      return res.status(400).json({ error: 'That is already your current location.' });
    }

    await pool.query(
      `UPDATE users SET
         pending_country = $1,
         pending_city = $2,
         location_change_reason = $3,
         location_change_status = 'pending'
       WHERE id = $4`,
      [countryInfo.code, city, reason, req.userId]
    );

    res.json({
      success: true,
      message: 'Request submitted. An admin must approve before your country/location changes.',
      location_change_status: 'pending',
      pending_country: countryInfo.code,
      pending_city: city,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not submit location change request.' });
  }
});

// GET - my location change request status
router.get('/location-change', requireAuth, async (req, res) => {
  try {
    await ensureAuthSchema();
    const result = await pool.query(
      `SELECT country, city, pending_country, pending_city, location_change_reason, location_change_status
       FROM users WHERE id = $1`,
      [req.userId]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load location change status.' });
  }
});

// POST - become a vendor (legacy simple form — kept for old app builds)
router.post('/become-vendor', requireAuth, async (req, res) => {
  const { business_name, business_bio, business_photo_url } = req.body;

  if (!business_name || !business_name.trim()) {
    return res.status(400).json({ error: 'Business name is required.' });
  }

  try {
    await ensureVendorColumns();
    await pool.query(
      `UPDATE users SET is_vendor = true, vendor_status = COALESCE(vendor_status, 'pending'),
         business_name = $1, business_bio = $2, business_photo_url = $3 WHERE id = $4`,
      [business_name.trim(), business_bio || null, business_photo_url || null, req.userId]
    );

    const userResult = await pool.query('SELECT referred_by FROM users WHERE id = $1', [req.userId]);
    const referredBy = userResult.rows[0]?.referred_by;

    if (referredBy) {
      await pool.query('UPDATE users SET free_featured_credits = free_featured_credits + 1 WHERE id = $1', [referredBy]);
      await pool.query('UPDATE users SET free_featured_credits = free_featured_credits + 1 WHERE id = $1', [req.userId]);
    }

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

// GET MY DIGEST NOTIFICATION SETTING
router.get('/digest-settings', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT digest_enabled FROM users WHERE id = $1', [req.userId]);
    res.json({ digest_enabled: result.rows[0]?.digest_enabled !== false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load digest settings.' });
  }
});

// PUT - toggle digest notifications on/off
router.put('/digest-settings', requireAuth, async (req, res) => {
  const { enabled } = req.body;

  try {
    await pool.query('UPDATE users SET digest_enabled = $1 WHERE id = $2', [enabled, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update digest settings.' });
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
