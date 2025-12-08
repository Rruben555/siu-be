const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const pool = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

// ================================
// JWT GENERATOR
// ================================
function generateToken(user) {
  const payload = {
    user_id: user.user_id,
    email: user.email,
    role: user.role
  };
  return jwt.sign(payload, process.env.JWT_SECRET || "dev_secret", { expiresIn: "7d" });
}

// ================================
// AUTH MIDDLEWARE
// ================================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token provided" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "dev_secret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Admin global
function adminOnly(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admin only" });

  next();
}

// Admin UKM (untuk role per-UKM)
async function adminUKM(req, res, next) {
  const user_id = req.user.user_id;
  const ukm_id = req.params.ukm_id;

  const q = await pool.query(
    "SELECT member_role FROM anggota WHERE user_id=$1 AND ukm_id=$2",
    [user_id, ukm_id]
  );

  if (q.rows.length === 0 || q.rows[0].member_role !== "admin") {
    return res.status(403).json({ error: "Not UKM admin" });
  }

  next();
}

// ==================================================
// AUTH: REGISTER
// ==================================================
app.post("/register", async (req, res) => {
  const { nama, nim, email, fakultas, password, role } = req.body;

  if (!nama || !email || !password || !fakultas)
    return res.status(400).json({ error: "Missing required fields" });

  try {
    const exists = await pool.query("SELECT 1 FROM users WHERE email=$1", [email]);
    if (exists.rows.length > 0)
      return res.status(409).json({ error: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);

    // Jika role kosong, otomatis jadi "user"
    const finalRole = role && role.trim() !== "" ? role : "user";

    const result = await pool.query(
      `INSERT INTO users (nama, nim, email, fakultas, password, role)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING user_id, email, role`,
      [nama, nim, email, fakultas, hashed, finalRole]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({ user, token });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// ==================================================
// AUTH: LOGIN (email + password)
// ==================================================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email & password required" });

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = generateToken(user);

    res.json({ user, token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// 6. GET CURRENT USER PROFILE (/me)
app.get("/me", auth, async (req, res) => { // Pastikan auth middleware terpasang
    try {
        const userId = req.user.user_id;

        // KOREKSI SELECT: Hapus 'username', Tambahkan 'fakultas'
        const userResult = await pool.query(
            "SELECT user_id, email, role, created_at, nama, nim, fakultas FROM users WHERE user_id=$1",
            [userId]
        );

        if (userResult.rows.length === 0)
            return res.status(404).json({ error: "User not found" });

        const user = userResult.rows[0];

        // KEANGGOTAAN DI UKM (Hapus U+00A0)
        const keanggotaanUkm = await pool.query(`
            SELECT a.ukm_id, a.member_role, u.nama AS ukm_nama, u.wa_group 
            FROM anggota a
            JOIN ukm u ON u.ukm_id = a.ukm_id
            WHERE a.user_id = $1
        `, [userId]);

        // KEGIATAN DI IKUTI (Hapus k.link_wa)
        const kegiatanDiikuti = await pool.query(`
            SELECT 
              p.registered_at, 
              k.event_id, 
              k.nama AS nama_kegiatan, 
              k.tanggal, 
              k.lokasi, 
              u.nama AS ukm_nama,
              u.wa_group AS ukm_wa_group 
            FROM participant p
            JOIN kegiatan k ON p.event_id = k.event_id
            JOIN ukm u ON k.ukm_id = u.ukm_id
            WHERE p.user_id = $1
            ORDER BY k.tanggal DESC
        `, [userId]);

        // -------------------------
        // FORMAT RESPONSE
        // -------------------------

        const response = {
            ...user,
            keanggotaan: keanggotaanUkm.rows,
            kegiatan_diikuti: kegiatanDiikuti.rows
        };

        res.json(response);

    } catch (err) {
        console.error("GET ME ERROR:", err);
        res.status(500).json({ error: "Server error", detail: err.message });
    }
});


// ==================================================
// UKM CRUD
// ==================================================
app.get("/ukm", async (req, res) => {
  const result = await pool.query("SELECT * FROM ukm ORDER BY ukm_id DESC");
  res.json(result.rows);
});

// Create UKM (admin only)
app.post("/ukm", auth, adminOnly, async (req, res) => {
  const { nama, deskripsi, gambar, wa_group } = req.body;
  const userId = req.user.user_id; // dari token JWT

  try {
    // 1. Buat UKM
    const result = await pool.query(
      `INSERT INTO ukm (nama, deskripsi, gambar, wa_group)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [nama, deskripsi, gambar, wa_group]
    );

    const ukm = result.rows[0];

    // 2. Tambahkan pembuat sebagai admin di tabel anggota
    await pool.query(
      `INSERT INTO anggota (user_id, ukm_id, member_role)
       VALUES ($1, $2, 'admin')`,
      [userId, ukm.ukm_id]
    );

    res.json({
      message: "UKM created and creator added as admin",
      ukm,
    });

  } catch (err) {
    console.error("CREATE UKM ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/ukm/:ukm_id", async (req, res) => {
  const { ukm_id } = req.params;

  try {
    // Detail UKM
    const ukm = await pool.query(
      `SELECT * FROM ukm WHERE ukm_id = $1`,
      [ukm_id]
    );

    if (ukm.rows.length === 0)
      return res.status(404).json({ error: "UKM not found" });

    // Anggota UKM
    const anggota = await pool.query(
      `SELECT a.member_role AS jabatan, u.user_id, u.nama, u.nim, u.email
       FROM anggota a
       JOIN users u ON u.user_id = a.user_id
       WHERE a.ukm_id = $1
       ORDER BY u.nama ASC`,
      [ukm_id]
    );

    // Kegiatan UKM
    const kegiatan = await pool.query(
      `SELECT event_id, nama, deskripsi, tanggal, lokasi, status
       FROM kegiatan
       WHERE ukm_id = $1
       ORDER BY tanggal DESC`,
      [ukm_id]
    );

    res.json({
      ...ukm.rows[0],
      anggota: anggota.rows,
      kegiatan: kegiatan.rows
    });

  } catch (err) {
    console.error("GET DETAIL UKM ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// Delete UKM (admin only)
app.delete("/ukm/:ukm_id", auth, adminOnly, async (req, res) => {
  await pool.query("DELETE FROM ukm WHERE ukm_id=$1", [req.params.ukm_id]);
  res.json({ message: "UKM deleted" });
});

// ==================================================
// JOIN UKM
// ==================================================
app.post("/ukm/:ukm_id/join", auth, async (req, res) => {
  try {
    const { ukm_id } = req.params;
    const user_id = req.user.user_id;

    const result = await pool.query(
      `INSERT INTO anggota (user_id, ukm_id)
       VALUES ($1,$2)
       ON CONFLICT (user_id, ukm_id) DO NOTHING
       RETURNING *`,
      [user_id, ukm_id]
    );

    res.json({
      message: "Joined UKM",
      data: result.rows[0] || "Already joined"
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error joining UKM" });
  }
});

// ==================================================
// LEAVE UKM
// ==================================================
app.delete("/ukm/:ukm_id/leave", auth, async (req, res) => {
  await pool.query(
    "DELETE FROM anggota WHERE user_id=$1 AND ukm_id=$2",
    [req.user.user_id, req.params.ukm_id]
  );
  res.json({ message: "Left UKM" });
});

// ==================================================
// KEGIATAN (EVENT)
// ==================================================
app.get("/kegiatan", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT k.*, u.nama AS ukm_nama
       FROM kegiatan k
       LEFT JOIN ukm u ON u.ukm_id = k.ukm_id
       ORDER BY k.created_at DESC`
    );

    res.json(result.rows);

  } catch (err) {
    console.error("GET KEGIATAN ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/kegiatan/:event_id", async (req, res) => {
  const { event_id } = req.params;

  try {
    // Ambil detail event
    const event = await pool.query(
      `SELECT k.*, u.nama AS ukm_nama
       FROM kegiatan k
       LEFT JOIN ukm u ON k.ukm_id = u.ukm_id
       WHERE k.event_id = $1`,
      [event_id]
    );

    if (event.rows.length === 0)
      return res.status(404).json({ error: "Event not found" });

    // Ambil peserta
    const peserta = await pool.query(
      `SELECT p.participant_id, p.registered_at,
              u.user_id, u.nama, u.email
       FROM participant p
       JOIN users u ON p.user_id = u.user_id
       WHERE p.event_id = $1`,
      [event_id]
    );

    res.json({
      event: event.rows[0],
      participants: peserta.rows
    });

  } catch (err) {
    console.error("GET EVENT DETAIL ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/ukm/:ukm_id/kegiatan", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM kegiatan WHERE ukm_id=$1 ORDER BY event_id DESC",
    [req.params.ukm_id]
  );
  res.json(result.rows);
});

// Create Event (UKM admin)
app.post("/ukm/:ukm_id/kegiatan", auth, adminUKM, async (req, res) => {
  const { nama, deskripsi, tanggal, lokasi, status } = req.body;
  const { ukm_id } = req.params;

  const q = await pool.query(
    `INSERT INTO kegiatan (ukm_id, nama, deskripsi, tanggal, lokasi, status)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING *`,
    [ukm_id, nama, deskripsi, tanggal, lokasi, status || "open"]
  );

  res.json(q.rows[0]);
});

// Delete Event (UKM admin)
app.delete("/kegiatan/:event_id", auth, async (req, res) => {
  await pool.query("DELETE FROM kegiatan WHERE event_id=$1", [
    req.params.event_id,
  ]);
  res.json({ message: "Event deleted" });
});

// ==================================================
// PARTICIPANT (DAFTAR EVENT)
// ==================================================
app.post("/kegiatan/:event_id/register", auth, async (req, res) => {
  const { event_id } = req.params;

  const q = await pool.query(
    `INSERT INTO participant (user_id, event_id)
     VALUES ($1,$2)
     ON CONFLICT(user_id,event_id) DO NOTHING
     RETURNING *`,
    [req.user.user_id, event_id]
  );

  res.json({
    message: "Registered to event",
    data: q.rows[0] || "Already registered"
  });
});

// ==================================================
// LAPORAN
// ==================================================
app.post("/ukm/:ukm_id/laporan", auth, adminUKM, async (req, res) => {
  const { peserta, biaya, catatan, event_id } = req.body;
  const { ukm_id } = req.params;

  const q = await pool.query(
    `INSERT INTO laporan (ukm_id, event_id, peserta, biaya, catatan)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING *`,
    [ukm_id, event_id || null, peserta || 0, biaya, catatan]
  );

  res.json(q.rows[0]);
});

app.get("/ukm/:ukm_id/laporan", async (req, res) => {
  const q = await pool.query(
    "SELECT * FROM laporan WHERE ukm_id=$1 ORDER BY report_id DESC",
    [req.params.ukm_id]
  );
  res.json(q.rows);
});

// Delete laporan
app.delete("/laporan/:id", auth, async (req, res) => {
  await pool.query("DELETE FROM laporan WHERE report_id=$1", [
    req.params.id,
  ]);
  res.json({ message: "Report deleted" });
});

// ======================
// ROOT ENDPOINT
// ======================
app.get("/", (req, res) => {
  res.send("Backend API for UKM System is running...");
});



// ======================
async function initServer() {
  try {
    await pool.query("SELECT NOW()");
    console.log("Database OK");
  } catch (err) {
    console.error("DB ERROR:", err);
  }
}

initServer();

app.listen(process.env.PORT || 4000, () =>
  console.log("Server running on port 4000")
);
