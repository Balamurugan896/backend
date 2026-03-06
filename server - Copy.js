// ─────────────────────────────────────────
//  EduMentor – Full Auth API Server
//  File: server.js
// ─────────────────────────────────────────

const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const mysql   = require('mysql2/promise');
const os      = require('os');
const { parentPort } = require('worker_threads');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
//  DATABASE CONNECTION
// ─────────────────────────────────────────
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',         // Change if you have password
  database: 'live',
  waitForConnections: true,
  connectionLimit: 10
});

// Test DB connection
(async () => {
  try {
    await db.query("SELECT 1");
    console.log("✅ MySQL Connected (live database)");
  } catch (err) {
    console.error("❌ MySQL Connection Failed:", err.message);
  }
})();

// ─────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────
const JWT_SECRET  = 'edu_mentor_super_secret_change_me';
const JWT_EXPIRES = '8h';

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────
//  HELPER: Find User
// ─────────────────────────────────────────
async function findUser(usernameOrEmail) {
  const [rows] = await db.execute(
    `SELECT id, username, full_name, email, role, password_hash, status
     FROM master_users
     WHERE LOWER(username) = LOWER(?) 
        OR LOWER(email) = LOWER(?)`,
    [usernameOrEmail, usernameOrEmail]
  );
  return rows[0];
}

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
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

// ✅ Users API
app.get('/api/users', (req, res) => {
  db.query('SELECT * FROM master_users', (err, results) => {
    if (err) {
      console.log("Query error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json(results);
  });
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
//  PROFILE (Protected)
// ─────────────────────────────────────────
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ─────────────────────────────────────────
//  HEALTH CHECK
// ─────────────────────────────────────────
app.get('/api/health', (req, res) => {
  db.query("SELECT 1", (err) => {
    if (err) {
      return res.json({ status: "error", database: "not connected" });
    }
    res.json({ status: "ok", database: "connected" });
  });
});

// ─────────────────────────────────────────
//  GET LOCAL IP (for LAN)
// ─────────────────────────────────────────
function getLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

const localIp = getLocalIp();

// ─────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log("\n🚀 EduMentor running at:");
  console.log(`   ➜ Local: http://localhost:${PORT}`);
  console.log(`   ➜ LAN:   http://${localIp}:${PORT}`);
});