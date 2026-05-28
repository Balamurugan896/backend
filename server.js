require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const mysql = require('mysql2');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
//  DATABASE CONNECTION (Aiven MySQL)
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

module.exports = pool;

// ─────────────────────────────────────────
//  IST TIMESTAMP HELPER
// ─────────────────────────────────────────
const getISTTimestamp = () => {
  const now = new Date();
  const ist = new Date(now.getTime() + 5.5 * 60 * 60 * 1000);
  return ist.toISOString().slice(0, 19).replace('T', ' ');
};

// ─────────────────────────────────────────
//  JWT CONFIG
// ─────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET || 'edu_mentor_super_secret_change_me';
const JWT_EXPIRES = '8h';

// ─────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────
//  AUTH HELPERS
// ─────────────────────────────────────────
async function findUser(usernameOrEmail) {
  const [rows] = await pool.execute(
    `SELECT id, username, full_name, email, role, password_hash, status
     FROM master_users
     WHERE LOWER(username) = LOWER(?)
        OR LOWER(email)    = LOWER(?)
     LIMIT 1`,
    [usernameOrEmail, usernameOrEmail]
  );
  return rows[0];
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token)
    return res.status(401).json({ success: false, message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
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
    await pool.execute('SELECT 1');
    res.json({ status: 'ok', database: 'connected', time_ist: getISTTimestamp() });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'not connected', detail: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ success: false, message: 'Username and password required' });

    const user = await findUser(username);

    if (!user)
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    if (user.status !== 'active')
      return res.status(403).json({ success: false, message: 'Account is inactive' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      success: true,
      token,
      user: {
        id:        user.id,
        username:  user.username,
        full_name: user.full_name,
        email:     user.email,
        role:      user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Protected profile route
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, full_name, email, role, status FROM master_users WHERE id = ?',
      [req.user.id]
    );
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 EduMentor API running on port ${PORT}`);
});
