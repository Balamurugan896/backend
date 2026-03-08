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
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

module.exports = pool;

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
     FROM master_users
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

// ─────────────────────────────────────────
//  USERS
//  GET  /api/users        — list all
//  POST /api/auth/register — create user
//  PUT  /api/users/:id    — update user
//  DELETE /api/users/:id  — delete user
//  PUT  /api/users/:id/toggle-status
// ─────────────────────────────────────────

// ─────────────────────────────────────────
//  REGISTER API
//  POST /api/auth/register
// ─────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    let { user_id, username, full_name, email, password, role } = req.body;

    // Validate required fields
    if (!user_id || !username || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: 'User ID, username, email, password and role are required'
      });
    }

    user_id  = user_id.trim();
    username = username.trim();
    email    = email.trim().toLowerCase();

    const allowedRoles = ['student', 'teacher', 'admin'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    // Check duplicate user_id, username or email
    const [existing] = await db.execute(
      `SELECT id FROM master_users 
       WHERE LOWER(user_id) = LOWER(?)  
          OR LOWER(email) = LOWER(?)`,
      [user_id, email]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'User ID or email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    await db.execute(
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
//  LOGIN API
//  POST /api/auth/login
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

    const user = await findUser(username.trim());

    if (!user || user.status !== 'active') {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    const payload = {
      id:       user.id,
      userid:   user.user_id,
      username: user.username,
      fullName: user.full_name,
      email:    user.email,
      role:     user.role
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
//  GET ACTIVE USERS LIST API
//  GET /api/users
// ─────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  try {

    const [rows] = await db.execute(
      `SELECT user_id, username, full_name, email, role, status
       FROM master_users
       WHERE status IN ('active', 'inactive')
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
//  TOGGLE USER STATUS API
//  PUT /api/users/:user_id/toggle-status
// ─────────────────────────────────────────
app.put('/api/users/:user_id/toggle-status', async (req, res) => {
  try {
    const { user_id } = req.params;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    // Check if user exists
    const [users] = await db.execute(
      `SELECT status FROM master_users WHERE user_id = ?`,
      [user_id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const currentStatus = users[0].status;
    const newStatus = currentStatus === 'active' ? 'inactive' : 'active';

    // Update status
    await db.execute(
      `UPDATE master_users SET status = ? WHERE user_id = ?`,
      [newStatus, user_id]
    );

    res.status(200).json({
      success: true,
      message: `User status updated to ${newStatus}`,
      data: {
        user_id,
        status: newStatus
      }
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
//  UPDATE USER API
//  PUT /api/users/:user_id
// ─────────────────────────────────────────
app.put('/api/users/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    let { username, full_name, email, role, password } = req.body;

    // Required fields (EXCEPT user_id & password)
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

    // Check duplicate email (except current user)
    const [existing] = await db.execute(
      `SELECT id FROM master_users 
       WHERE LOWER(email) = LOWER(?) 
         AND user_id != ?`,
      [email, user_id]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // If password provided → hash it
    let query;
    let values;

    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);

      query = `
        UPDATE master_users
        SET username = ?,
            full_name = ?,
            email = ?,
            role = ?,
            password_hash = ?,
            status = 'active'
        WHERE user_id = ?
      `;

      values = [
        username,
        full_name || null,
        email,
        role,
        hashedPassword,
        user_id
      ];

    } else {
      // No password update
      query = `
        UPDATE master_users
        SET username = ?,
            full_name = ?,
            email = ?,
            role = ?,
            status = 'active'
        WHERE user_id = ?
      `;

      values = [
        username,
        full_name || null,
        email,
        role,
        user_id
      ];
    }

    const [result] = await db.execute(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
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
//  DELETE USER API (Soft Delete)
//  DELETE /api/users/:user_id
// ─────────────────────────────────────────

app.delete('/api/users/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;

    const [result] = await db.execute(
      `UPDATE master_users 
       SET status = 'delete'
       WHERE user_id = ?`,
      [user_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'User deactivated successfully'
    });

  } catch (err) {
    console.error('Soft Delete Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
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
