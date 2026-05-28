require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
// DATABASE CONNECTION (MySQL Pool)
// ─────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 16587,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  ssl: { rejectUnauthorized: false },

  waitForConnections: true,
  connectionLimit: 10,
  connectTimeout: 20000,
}).promise();

// ─────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────
// JWT CONFIG
// ─────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'edu_mentor_super_secret_change_me';
const JWT_EXPIRES = '8h';

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────
const getISTTimestamp = () => {
  const now = new Date();
  const ist = new Date(now.getTime() + 5.5 * 60 * 60 * 1000);
  return ist.toISOString().slice(0, 19).replace('T', ' ');
};

async function findUser(usernameOrEmail) {
  const [rows] = await pool.execute(
    `SELECT id, username, full_name, email, role, password_hash, status
     FROM master_users
     WHERE LOWER(username) = LOWER(?)
        OR LOWER(email) = LOWER(?)
     LIMIT 1`,
    [usernameOrEmail, usernameOrEmail]
  );

  return rows[0];
}

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({
      status: 'ok',
      database: 'connected',
      time_ist: getISTTimestamp()
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      database: 'not connected',
      detail: err.message
    });
  }
});

// ─────────────────────────────────────────
// DATABASE: MYSQL2 (POOL REQUIRED)
// ─────────────────────────────────────────
// const mysql = require('mysql2/promise');
// const pool = mysql.createPool({...});

// ─────────────────────────────────────────
//  USERS
//  GET  /api/users        — list all
//  POST /api/auth/register — create user
//  PUT  /api/users/:id    — update user
//  DELETE /api/users/:id  — delete user
//  PUT  /api/users/:id/toggle-status
// ─────────────────────────────────────────

// ─────────────────────────────────────────
// REGISTER USER
// POST /api/auth/register
// ─────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    let { user_id, username, full_name, email, password, role } = req.body;

    if (!user_id || !username || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: 'User ID, username, email, password and role are required'
      });
    }

    user_id = user_id.trim();
    username = username.trim();
    email = email.trim().toLowerCase();

    const allowedRoles = ['student', 'teacher', 'admin'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    // Check duplicate
    const [existing] = await pool.query(
      `SELECT id FROM master_users
       WHERE LOWER(user_id) = LOWER(?) OR LOWER(email) = LOWER(?)`,
      [user_id, email]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'User ID or email already exists'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO master_users
       (user_id, username, full_name, email, role, password_hash)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [user_id, username, full_name || null, email, role, hashedPassword]
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully'
    });

  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
// LOGIN USER
// POST /api/auth/login
// ─────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    const [rows] = await pool.query(
      `SELECT * FROM master_users WHERE username = ?`,
      [username.trim()]
    );

    if (rows.length === 0 || rows[0].status !== 'active') {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    const user = rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    const payload = {
      id: user.id,
      user_id: user.user_id,
      username: user.username,
      full_name: user.full_name,
      email: user.email,
      role: user.role
    };

    const token = jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: payload
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
// GET ALL USERS
// GET /api/users
// ─────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT user_id, username, full_name, email, role, status
       FROM master_users
       WHERE status IN ('active','inactive')
       ORDER BY user_id ASC`
    );

    res.status(200).json({
      success: true,
      count: rows.length,
      data: rows
    });

  } catch (err) {
    console.error('Users List Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
// TOGGLE USER STATUS
// PUT /api/users/:user_id/toggle-status
// ─────────────────────────────────────────
app.put('/api/users/:user_id/toggle-status', async (req, res) => {
  try {
    const { user_id } = req.params;

    const [rows] = await pool.query(
      `SELECT status FROM master_users WHERE user_id = ?`,
      [user_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const newStatus = rows[0].status === 'active' ? 'inactive' : 'active';

    await pool.query(
      `UPDATE master_users SET status = ? WHERE user_id = ?`,
      [newStatus, user_id]
    );

    res.json({
      success: true,
      message: `User status updated to ${newStatus}`,
      data: { user_id, status: newStatus }
    });

  } catch (err) {
    console.error('Toggle Status Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
// UPDATE USER
// PUT /api/users/:user_id
// ─────────────────────────────────────────
app.put('/api/users/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    let { username, full_name, email, role, password } = req.body;

    if (!username || !email || !role) {
      return res.status(400).json({
        success: false,
        message: 'Username, email and role are required'
      });
    }

    username = username.trim();
    email = email.trim().toLowerCase();

    const allowedRoles = ['student', 'teacher', 'admin'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    const [checkEmail] = await pool.query(
      `SELECT user_id FROM master_users
       WHERE LOWER(email) = LOWER(?)
       AND user_id != ?`,
      [email, user_id]
    );

    if (checkEmail.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.query(
        `UPDATE master_users
         SET username=?, full_name=?, email=?, role=?, password_hash=?, status='active'
         WHERE user_id=?`,
        [username, full_name || null, email, role, hashedPassword, user_id]
      );

    } else {
      await pool.query(
        `UPDATE master_users
         SET username=?, full_name=?, email=?, role=?, status='active'
         WHERE user_id=?`,
        [username, full_name || null, email, role, user_id]
      );
    }

    res.json({
      success: true,
      message: 'User updated successfully'
    });

  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
// DELETE USER (SOFT DELETE)
// DELETE /api/users/:user_id
// ─────────────────────────────────────────
app.delete('/api/users/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;

    const [result] = await pool.query(
      `UPDATE master_users SET status='deleted' WHERE user_id=?`,
      [user_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (err) {
    console.error('Delete Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Profile (protected)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, username, full_name, email, role, status
       FROM master_users
       WHERE id = ?`,
      [req.user.id]
    );

    res.json({
      success: true,
      user: rows[0]
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 EduMentor API running on port ${PORT}`);
});
