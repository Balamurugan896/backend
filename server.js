require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
//  DATABASE CONNECTION (Supabase PostgreSQL)
// ─────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// ─────────────────────────────────────────
//  JWT CONFIG
// ─────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'edu_mentor_super_secret_change_me';
const JWT_EXPIRES = '8h';

// ─────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────
//  AUTH HELPER
// ─────────────────────────────────────────
async function findUser(usernameOrEmail) {
  const { rows } = await pool.query(
    `SELECT id, username, full_name, email, role, password_hash, status
     FROM users
     WHERE LOWER(username) = LOWER($1)
        OR LOWER(email) = LOWER($2)
     LIMIT 1`,
    [usernameOrEmail, usernameOrEmail]
  );
  return rows[0];
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ─────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'not connected', detail: err.message });
  }
});

// Register user
app.post('/api/auth/register', async (req, res) => {
  const { username, full_name, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ success: false, message: 'Missing fields' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO master_users (username, full_name, email, password_hash, role, status)
       VALUES ($1, $2, $3, $4, 'user', true) RETURNING id, username, email`,
      [username, full_name, email, hashedPassword]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) return res.status(400).json({ success: false, message: 'Missing fields' });

  try {
    const user = await findUser(usernameOrEmail);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ success: false, message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, username, full_name, email, role, status FROM users');
    res.json({ success: true, users: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Update user
app.put('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { full_name, email, role } = req.body;
  try {
    const result = await pool.query(
      `UPDATE master_users SET full_name=$1, email=$2, role=$3 WHERE id=$4 RETURNING id, username, full_name, email, role`,
      [full_name, email, role, id]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Delete user
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM master_users WHERE id=$1', [id]);
    res.json({ success: true, message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Toggle user status
app.put('/api/users/:id/toggle-status', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE master_users SET status = NOT status WHERE id=$1 RETURNING id, username, status`,
      [id]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Protected profile route
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, username, full_name, email, role, status FROM master_users WHERE id=$1', [req.user.id]);
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 EduMentor API running on port ${PORT}`);
});
