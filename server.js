// ─────────────────────────────────────────
//  EduMentor – Full Auth API Server
//  File: server.js
// ─────────────────────────────────────────

const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const mysql   = require('mysql2/promise');  // ← promise-based: always use await
const os      = require('os');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
//  DATABASE CONNECTION
// ─────────────────────────────────────────
const db = mysql.createPool({
  host:             'localhost',
  user:             'root',
  password:         '',         // Change if you have a password
  database:         'live',
  waitForConnections: true,
  connectionLimit:  10
});

// Test DB connection on startup
(async () => {
  try {
    await db.query('SELECT 1');
    console.log('✅ MySQL Connected (live database)');
  } catch (err) {
    console.error('❌ MySQL Connection Failed:', err.message);
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
//  HELPER: Find User by username OR email
// ─────────────────────────────────────────
async function findUser(usernameOrEmail) {
  const [rows] = await db.execute(
    `SELECT id, user_id, username, full_name, email, role, password_hash, status
     FROM master_users
     WHERE LOWER(username) = LOWER(?)
        OR LOWER(email)    = LOWER(?)`,
    [usernameOrEmail, usernameOrEmail]
  );
  return rows[0];
}

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1];

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
//  HEALTH CHECK
//  GET /api/health
// ─────────────────────────────────────────
app.get('/api/health', async (req, res) => {         // ✅ async
  try {
    await db.query('SELECT 1');                       // ✅ await — no callback
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

// ─────────────────────────────────────────
//  TEACHER REGISTER API
//  POST /api/teachers/register
// ─────────────────────────────────────────
app.post('/api/teachers/register', async (req, res) => {
  try {
    let {
      teacher_id,
      teacher_name,
      role,
      category,

      tamil, english, maths, social, social_science, others,

      class_1, class_2, class_3, class_4, class_5,
      class_6, class_7, class_8, class_9, class_10,

      contact_no,
      address,
      emergency_contact,
      blood_group,
      qualification
    } = req.body;

    // ✅ Required fields validation
    if (!teacher_id || !teacher_name || !role || !category) {
      return res.status(400).json({
        success: false,
        message: 'Teacher code, name, role and category are required'
      });
    }

    teacher_id = teacher_id.trim();
    teacher_name = teacher_name.trim();

    const allowedRoles = ['teacher', 'trainee'];
    const allowedCategory = ['permanent', 'temporary'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    if (!allowedCategory.includes(category)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid category'
      });
    }

    // ✅ Check duplicate teacher_id
    const [existing] = await db.execute(
      `SELECT id FROM master_teacher WHERE teacher_id = ?`,
      [teacher_id]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Teacher code already exists'
      });
    }

    // ✅ Convert undefined to false (checkbox handling)
    const bool = (val) => val ? true : false;

    await db.execute(
      `INSERT INTO master_teacher (
        teacher_id, teacher_name, role, category,
        tamil, english, maths, social, social_science, others,
        class_1, class_2, class_3, class_4, class_5,
        class_6, class_7, class_8, class_9, class_10,
        contact_no, address, emergency_contact,
        blood_group, qualification
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        teacher_id,
        teacher_name,
        role,
        category,

        bool(tamil),
        bool(english),
        bool(maths),
        bool(social),
        bool(social_science),
        bool(others),

        bool(class_1),
        bool(class_2),
        bool(class_3),
        bool(class_4),
        bool(class_5),
        bool(class_6),
        bool(class_7),
        bool(class_8),
        bool(class_9),
        bool(class_10),

        contact_no || null,
        address || null,
        emergency_contact || null,
        blood_group || null,
        qualification || null
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Teacher registered successfully'
    });

  } catch (err) {
    console.error('Teacher Register Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  GET TEACHERS LIST API
//  GET /api/teachers
// ─────────────────────────────────────────
app.get('/api/teachers', async (req, res) => {
  try {

    const [rows] = await db.execute(
      `SELECT 
          teacher_id,
          teacher_name,
          role,
          category,
          tamil,
          english,
          maths,
          social,
          social_science,
          others,
          class_1,
          class_2,
          class_3,
          class_4,
          class_5,
          class_6,
          class_7,
          class_8,
          class_9,
          class_10,
          contact_no,
          address,
          emergency_contact,
          blood_group,
          qualification,
          status,
          created_at
       FROM master_teacher
       WHERE status IN ('active', 'inactive')
       ORDER BY teacher_id ASC`
    );

    res.status(200).json({
      success: true,
      count: rows.length,
      data: rows
    });

  } catch (err) {
    console.error('Teachers List Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  TOGGLE TEACHER STATUS API
//  PUT /api/teachers/:teacher_id/toggle-status
// ─────────────────────────────────────────
app.put('/api/teachers/:teacher_id/toggle-status', async (req, res) => {
  try {
    const { teacher_id } = req.params;

    if (!teacher_id) {
      return res.status(400).json({
        success: false,
        message: 'Teacher Code is required'
      });
    }

    // Check if teacher exists
    const [teachers] = await db.execute(
      `SELECT status FROM master_teacher WHERE teacher_id = ?`,
      [teacher_id]
    );

    if (teachers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Teacher not found'
      });
    }

    const currentStatus = teachers[0].status;

    if (!['active', 'inactive'].includes(currentStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid teacher status'
      });
    }

    const newStatus = currentStatus === 'active' ? 'inactive' : 'active';

    // Update teacher status
    await db.execute(
      `UPDATE master_teacher 
       SET status = ? 
       WHERE teacher_id = ?`,
      [newStatus, teacher_id]
    );

    res.status(200).json({
      success: true,
      message: `Teacher status updated to ${newStatus}`,
      data: {
        teacher_id,
        status: newStatus
      }
    });

  } catch (err) {
    console.error('Toggle Teacher Status Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  TEACHER UPDATE API
//  PUT /api/teachers/:teacher_id
// ─────────────────────────────────────────
app.put('/api/teachers/:teacher_id', async (req, res) => {
  try {
    const { teacher_id } = req.params;

    let {
      teacher_name,
      role,
      category,

      tamil, english, maths, social, social_science, others,

      class_1, class_2, class_3, class_4, class_5,
      class_6, class_7, class_8, class_9, class_10,

      contact_no,
      address,
      emergency_contact,
      blood_group,
      qualification
    } = req.body;

    // ✅ Required fields
    if (!teacher_name || !role || !category) {
      return res.status(400).json({
        success: false,
        message: 'Teacher name, role and category are required'
      });
    }

    teacher_name = teacher_name.trim();

    const allowedRoles = ['teacher', 'trainee'];
    const allowedCategory = ['permanent', 'temporary'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role'
      });
    }

    if (!allowedCategory.includes(category)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid category'
      });
    }

    // ✅ If you allow editing teacher_id from body, check duplicate
    if (req.body.teacher_id && req.body.teacher_id !== teacher_id) {

      const [existing] = await db.execute(
        `SELECT id FROM master_teacher 
         WHERE teacher_id = ? 
         AND teacher_id != ?`,
        [req.body.teacher_id, teacher_id]
      );

      if (existing.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Teacher code already exists'
        });
      }
    }

    // ✅ Convert checkbox values
    const bool = (val) => val ? true : false;

    const [result] = await db.execute(
      `UPDATE master_teacher SET
        teacher_name = ?,
        role = ?,
        category = ?,

        tamil = ?, 
        english = ?, 
        maths = ?, 
        social = ?, 
        social_science = ?, 
        others = ?,

        class_1 = ?, 
        class_2 = ?, 
        class_3 = ?, 
        class_4 = ?, 
        class_5 = ?,
        class_6 = ?, 
        class_7 = ?, 
        class_8 = ?, 
        class_9 = ?, 
        class_10 = ?,

        contact_no = ?, 
        address = ?, 
        emergency_contact = ?,
        blood_group = ?, 
        qualification = ?

       WHERE teacher_id = ?`,
      [
        teacher_name,
        role,
        category,

        bool(tamil),
        bool(english),
        bool(maths),
        bool(social),
        bool(social_science),
        bool(others),

        bool(class_1),
        bool(class_2),
        bool(class_3),
        bool(class_4),
        bool(class_5),
        bool(class_6),
        bool(class_7),
        bool(class_8),
        bool(class_9),
        bool(class_10),

        contact_no || null,
        address || null,
        emergency_contact || null,
        blood_group || null,
        qualification || null,

        teacher_id
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Teacher not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Teacher updated successfully'
    });

  } catch (err) {
    console.error('Teacher Update Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  DELETE TEACHER (SOFT DELETE)
//  DELETE /api/teachers/:teacher_id
// ─────────────────────────────────────────
app.delete('/api/teachers/:teacher_id', async (req, res) => {
  try {
    const { teacher_id } = req.params;

    if (!teacher_id) {
      return res.status(400).json({
        success: false,
        message: 'Teacher ID is required'
      });
    }

    // Check if teacher exists
    const [rows] = await db.execute(
      `SELECT teacher_id FROM master_teacher WHERE teacher_id = ?`,
      [teacher_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Teacher not found'
      });
    }

    // Soft delete (change status)
    await db.execute(
      `UPDATE master_teacher 
       SET status = 'delete' 
       WHERE teacher_id = ?`,
      [teacher_id]
    );

    res.status(200).json({
      success: true,
      message: 'Teacher deleted successfully'
    });

  } catch (err) {
    console.error('Delete Teacher Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  CLASSES REGISTER API
//  POST /api/classes
// ─────────────────────────────────────────
app.post('/api/classes', async (req, res) => {
  try {
    const { class_code, class_name, class_order } = req.body;

    // Validate required fields
    if (!class_code || !class_name || !class_order) {
      return res.status(400).json({
        success: false,
        message: 'class_code, class_name, and class_order are required'
      });
    }

    // Check if class_code already exists (unique)
    const [existing] = await db.execute(
      `SELECT class_code FROM master_class WHERE class_code = ?`,
      [class_code]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Class Code already exists'
      });
    }

    // Insert new class
    await db.execute(
      `INSERT INTO master_class (class_code, class_name, class_order)
       VALUES (?, ?, ?)`,
      [class_code, class_name, class_order]
    );

    res.status(201).json({
      success: true,
      message: 'Class registered successfully'
    });

  } catch (err) {
    console.error('Register Class Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  CLASSES LIST API
//  GET /api/classes
// ─────────────────────────────────────────
app.get('/api/classes', async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT
          id,
          class_code,
          class_name,
          class_order,
          status
       FROM master_class
       ORDER BY class_order ASC`
    );

    res.status(200).json({
      success: true,
      count: rows.length,
      data: rows
    });

  } catch (err) {
    console.error('Class List Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  TOGGLE CLASS STATUS API
//  PUT /api/classes/:id/toggle-status
// ─────────────────────────────────────────
app.put('/api/classes/:id/toggle-status', async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'Class Code is required'
      });
    }

    // Check if class exists
    const [classes] = await db.execute(
      `SELECT status FROM master_class WHERE id = ?`,
      [id]
    );

    if (classes.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Class not found'
      });
    }

    const currentStatus = classes[0].status;

    // Validate status
    if (!['active', 'inactive'].includes(currentStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid class status'
      });
    }

    const newStatus = currentStatus === 'active' ? 'inactive' : 'active';

    // Update class status
    await db.execute(
      `UPDATE master_class 
       SET status = ? 
       WHERE id = ?`,
      [newStatus, id]
    );

    res.status(200).json({
      success: true,
      message: `Class status updated to ${newStatus}`,
      data: {
        id,
        status: newStatus
      }
    });

  } catch (err) {
    console.error('Toggle Class Status Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  UPDATE CLASS API
//  PUT /api/classes/:id
// ─────────────────────────────────────────
app.put('/api/classes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { class_name, class_order } = req.body;  // class_code is read-only, not updated

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'Class ID is required'
      });
    }

    // Validate required fields
    if (!class_name || !class_order) {
      return res.status(400).json({
        success: false,
        message: 'Class name and order are required'
      });
    }

    // Check if class exists
    const [existing] = await db.execute(
      `SELECT id FROM master_class WHERE id = ?`,
      [id]
    );

    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Class not found'
      });
    }

    // Update class
    await db.execute(
      `UPDATE master_class 
       SET class_name = ?, class_order = ?
       WHERE id = ?`,
      [class_name, class_order, id]
    );

    // Return updated data
    const [updated] = await db.execute(
      `SELECT id, class_code, class_name, class_order, status 
       FROM master_class WHERE id = ?`,
      [id]
    );

    res.status(200).json({
      success: true,
      message: 'Class updated successfully',
      data: updated[0]
    });

  } catch (err) {
    console.error('Update Class Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  DELETE CLASS API (Soft Delete)
//  DELETE /api/classes/:id
// ─────────────────────────────────────────
app.delete('/api/classes/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await db.execute(
      `UPDATE master_class 
       SET status = 'delete'
       WHERE id = ?`,
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Class not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Class deleted successfully'
    });

  } catch (err) {
    console.error('Soft Delete Error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// ─────────────────────────────────────────
//  PROFILE (protected)
//  GET /api/profile
// ─────────────────────────────────────────
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ─────────────────────────────────────────
//  GET LOCAL IP
// ─────────────────────────────────────────
function getLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return 'localhost';
}

// ─────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  const localIp = getLocalIp();
  console.log('\n🚀 EduMentor API running at:');
  console.log(`   ➜ Local : http://localhost:${PORT}`);
  console.log(`   ➜ LAN   : http://${localIp}:${PORT}`);
  console.log('\n📋 Available endpoints:');
  console.log(`   GET    /api/health`);
  console.log(`   POST   /api/auth/login`);
  console.log(`   POST   /api/auth/register`);
  console.log(`   GET    /api/users`);
  console.log(`   PUT    /api/users/:user_id`);
  console.log(`   DELETE /api/users/:user_id`);
  console.log(`   PUT    /api/users/:user_id/toggle-status`);
  console.log(`   GET    /api/profile  (protected)\n`);
});