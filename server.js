// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./db"); // pastikan db.js meng-export pool pg (pg.Pool)
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "secret_dev";

function generateToken(user) {
  // include minimal info in token
  return jwt.sign(
    { user_id: user.user_id, role: user.role || "user" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ---------------------------
// Middleware
// ---------------------------

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token provided" });

  const token = header.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

function ukmAdminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== "ukm_admin" && req.user.role !== "admin")
    return res.status(403).json({ error: "UKM admin only" });
  next();
}

// ---------------------------
// Routes
// ---------------------------

// 1) REGISTER (public) - create new user
app.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "username, email, password required" });
    }

    // basic checks
    const exists = await pool.query(
      "SELECT 1 FROM users WHERE username=$1 OR email=$2",
      [username, email]
    );
    if (exists.rows.length > 0)
      return res.status(409).json({ error: "username or email already taken" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password, role)
       VALUES ($1,$2,$3,$4)
       RETURNING user_id, username, email, role, created_at`,
      [username, email, hashed, role || "user"]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({ user, token });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// 2) LOGIN (public) - by email or username support
app.post("/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if ((!email && !username) || !password)
      return res.status(400).json({ error: "Provide email or username and password" });

    const result = await pool.query(
      email ? "SELECT * FROM users WHERE email=$1" : "SELECT * FROM users WHERE username=$1",
      [email || username]
    );

    if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = generateToken(user);
    // do not send password back
    delete user.password;
    res.json({ user, token });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// 3) FORGOT / CHANGE PASSWORD (public by email) - put change password
// This route allows setting new password given email (you might want to secure with email token in production)
app.put("/change-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ error: "email and newPassword required" });

    const hashed = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      "UPDATE users SET password=$1 WHERE email=$2 RETURNING user_id",
      [hashed, email]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: "Email not found" });

    res.json({ message: "Password updated" });
  } catch (err) {
    console.error("CHANGE PASSWORD ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// 3b) Authenticated change password (user changes own password)
app.put("/users/:id/password", auth, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (req.user.user_id !== userId && req.user.role !== "admin")
      return res.status(403).json({ error: "Not allowed" });

    const { currentPassword, newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: "newPassword required" });

    // If currentPassword provided, verify
    const u = await pool.query("SELECT password FROM users WHERE user_id=$1", [userId]);
    if (u.rows.length === 0) return res.status(404).json({ error: "User not found" });

    if (currentPassword) {
      const ok = await bcrypt.compare(currentPassword, u.rows[0].password);
      if (!ok) return res.status(400).json({ error: "currentPassword incorrect" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password=$1 WHERE user_id=$2", [hashed, userId]);
    res.json({ message: "Password changed" });
  } catch (err) {
    console.error("AUTH CHANGE PASSWORD ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// 4) GET ALL USERS (admin only)
app.get("/users", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT user_id, username, email, role, created_at FROM users ORDER BY user_id ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// 5) DELETE USER (admin only)
app.delete("/users/:id", auth, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query("DELETE FROM users WHERE user_id=$1", [id]);
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error("DELETE USER ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// ---------------------------
// UKM endpoints
// ---------------------------

// =======================================================
//                EVENT ENDPOINTS (NEW STRUCTURE)
// =======================================================

app.get("/ukm", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM ukm ORDER BY ukm_id ASC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch UKM list" });
  }
});

// 1. GET all events for a specific UKM
app.get("/ukm/:ukm_id", async (req, res) => {
  try {
    const { ukm_id } = req.params;

    const result = await pool.query(
      `SELECT * FROM ukm_events 
       WHERE ukm_id = $1
       ORDER BY tanggal ASC NULLS LAST`,
      [ukm_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("GET UKM EVENTS ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// 2. GET detail event
app.get("/ukm/events/:event_id", async (req, res) => {
  try {
    const { event_id } = req.params;

    const result = await pool.query(
      `SELECT e.*, u.nama AS ukm_nama 
       FROM ukm_events e
       LEFT JOIN ukm u ON u.ukm_id = e.ukm_id
       WHERE event_id = $1`,
      [event_id]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Event not found" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET EVENT DETAIL ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// 3. CREATE event for UKM (only ukm_admin)
app.post("/ukm/:ukm_id/events", auth, ukmAdminOnly, async (req, res) => {
  try {
    const { ukm_id } = req.params;
    const { nama, deskripsi, tanggal, lokasi } = req.body;

    if (!nama) return res.status(400).json({ error: "nama is required" });

    const result = await pool.query(
      `INSERT INTO ukm_events (ukm_id, nama, deskripsi, tanggal, lokasi)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [ukm_id, nama, deskripsi || null, tanggal || null, lokasi || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("CREATE EVENT ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// 4. UPDATE event
app.put("/ukm/events/:event_id", auth, ukmAdminOnly, async (req, res) => {
  try {
    const { event_id } = req.params;
    const { nama, deskripsi, tanggal, lokasi } = req.body;

    const result = await pool.query(
      `UPDATE ukm_events
       SET nama = $1,
           deskripsi = $2,
           tanggal = $3,
           lokasi = $4
       WHERE event_id = $5
       RETURNING *`,
      [nama, deskripsi || null, tanggal || null, lokasi || null, event_id]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Event not found" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("UPDATE EVENT ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// 5. DELETE event
app.delete("/ukm/events/:event_id", auth, ukmAdminOnly, async (req, res) => {
  try {
    const { event_id } = req.params;

    const result = await pool.query(
      `DELETE FROM ukm_events WHERE event_id = $1 RETURNING *`,
      [event_id]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Event not found" });

    res.json({ message: "Event deleted" });
  } catch (err) {
    console.error("DELETE EVENT ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// =======================================================
//          EVENT REGISTRATION (JOIN & UNJOIN)
// =======================================================


// 6. REGISTER to event
app.post("/ukm/events/:event_id/register", auth, async (req, res) => {
  try {
    const { event_id } = req.params;

    const result = await pool.query(
      `INSERT INTO ukm_event_participants (user_id, event_id)
       VALUES ($1,$2)
       RETURNING *`,
      [req.user.user_id, event_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("REGISTER EVENT ERROR:", err);

    if (err.code === "23505")
      return res.status(409).json({ error: "Already registered" });

    res.status(500).json({ error: "Server error", detail: err.message });
  }
});


// 7. UNREGISTER from event
app.delete("/ukm/events/:event_id/unregister", auth, async (req, res) => {
  try {
    const { event_id } = req.params;

    const result = await pool.query(
      `DELETE FROM ukm_event_participants
       WHERE user_id = $1 AND event_id = $2
       RETURNING *`,
      [req.user.user_id, event_id]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Not registered to event" });

    res.json({ message: "Unregistered from event" });
  } catch (err) {
    console.error("UNREGISTER EVENT ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// Get participants (admin/ukm_admin)
app.get("/ukm/events/:eventId/participants", auth, ukmAdminOnly, async (req, res) => {
  try {
    const eventId = Number(req.params.eventId);

    const result = await pool.query(
      `SELECT 
        p.participant_id, 
        p.registered_at, 
        u.user_id, 
        u.username, 
        u.email
       FROM ukm_event_participants p
       JOIN users u ON u.user_id = p.user_id
       WHERE p.event_id = $1
       ORDER BY p.registered_at`,
      [eventId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("GET PARTICIPANTS ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// ---------------------------
// small util: get current user profile
// ---------------------------
app.get("/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT user_id, username, email, role, created_at FROM users WHERE user_id=$1",
      [req.user.user_id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "User not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET ME ERROR:", err);
    res.status(500).json({ error: "Server error", detail: err.message });
  }
});

// ---------------------------
// Start server
// ---------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
