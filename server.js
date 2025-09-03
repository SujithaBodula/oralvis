// ====== DEPENDENCIES ======
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");
const PDFDocument = require("pdfkit");
const axios = require("axios");
const path = require("path");

// ====== APP SETUP ======
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Basic in-file CSS
const CSS = `
:root { --bg:#0f172a; --card:#111827; --ink:#e5e7eb; --ink2:#9ca3af; --brand:#06b6d4; --muted:#334155; }
* { box-sizing: border-box; }
body { margin:0; font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background: var(--bg); color: var(--ink); }
a { color: var(--brand); text-decoration: none; }
.container { max-width: 980px; margin: 40px auto; padding: 24px; background: #0b1220; border: 1px solid #1f2937; border-radius: 16px; }
header { display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px; }
h1, h2 { margin: 0 0 12px; }
label { display:block; font-size: 14px; color: var(--ink2); margin: 10px 0 6px; }
input, select { width:100%; padding:12px 14px; background:#0a0f1a; color: var(--ink); border:1px solid #1f2937; border-radius:10px; outline:none; }
button { background: linear-gradient(90deg, #06b6d4, #22d3ee); color:#001018; font-weight:700; border:none; padding:12px 16px; border-radius:10px; cursor:pointer; }
.btn-secondary { background:#101826; color:#e2e8f0; border:1px solid #1f2937; }
.row { display:grid; grid-template-columns: repeat(2, 1fr); gap:14px; }
.card { background: var(--card); border:1px solid #1f2937; border-radius:14px; padding:16px; }
.grid { display:grid; gap:14px; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }
img.thumb { width:100%; height:170px; object-fit:cover; border-radius:10px; border:1px solid #1f2937; background:#0a0f1a; }
.meta { font-size: 12px; color: var(--ink2); margin: 6px 0 2px; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #1f2937; color:#93c5fd; background:#0b1220; font-size:12px; }
.table { width:100%; border-collapse: collapse; }
.table th, .table td { border-bottom: 1px solid #1f2937; padding: 10px; text-align:left; }
hr { border: none; border-top:1px solid #1f2937; margin: 16px 0; }
footer { text-align:center; color:var(--ink2); margin: 24px 0; }
.notice { background:#052e2e; border:1px solid #134e4a; color:#a7f3d0; padding:10px 12px; border-radius:12px; }
.error { background:#3f1d1d; border:1px solid #7f1d1d; color:#fecaca; padding:10px 12px; border-radius:12px; }
`;

// ====== CLOUDINARY ======
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
  api_key: process.env.CLOUDINARY_API_KEY || "",
  api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

// ====== DATABASE ======
const db = new sqlite3.Database(path.join(__dirname, "oralvis.db"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('Technician', 'Dentist')) NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_name TEXT NOT NULL,
      patient_id TEXT NOT NULL,
      scan_type TEXT CHECK(scan_type IN ('RGB')) NOT NULL,
      region TEXT CHECK(region IN ('Frontal', 'Upper Arch', 'Lower Arch')) NOT NULL,
      image_url TEXT NOT NULL,
      uploaded_at TEXT NOT NULL,
      technician_email TEXT NOT NULL
    )
  `);

  // Seed users if not exist
  const seed = (email, pwd, role) => {
    db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, row) => {
      if (err) return console.error("DB error:", err);
      if (row) return;
      const hash = bcrypt.hashSync(pwd, 10);
      db.run(
        `INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)`,
        [email, hash, role]
      );
    });
  };
  seed("tech@oralvis.com", "tech123", "Technician");
  seed("dentist@oralvis.com", "dent123", "Dentist");
});

// ====== AUTH HELPERS ======
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login?msg=Please%20login");
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect("/login?msg=Please%20login");
    if (req.session.user.role !== role)
      return res
        .status(403)
        .send(htmlPage("Forbidden", `<div class="container"><p class="error">Access denied.</p><p><a href="/">Go home</a></p></div>`));
    next();
  };
}

// ====== VIEWS ======
const layout = (title, body, user, msg) => `<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width">
<title>${title} • OralVis</title><style>${CSS}</style></head>
<body>
  <div class="container">
    <header>
      <div><h1>OralVis Healthcare</h1><div class="meta">Basic demo · SQLite · Cloudinary · PDF</div></div>
      <div>
        ${
          user
            ? `<span class="badge">${user.role}</span> <span class="meta">${user.email}</span> &nbsp;
               <a class="btn-secondary" href="/logout"><button class="btn-secondary">Logout</button></a>`
            : `<a href="/login"><button>Login</button></a>`
        }
      </div>
    </header>
    ${msg ? `<div class="notice">${msg}</div>` : ""}
    ${body}
    <footer>© ${new Date().getFullYear()} OralVis Demo</footer>
  </div>
</body></html>`;

const htmlPage = (title, content, user = null, msg = "") => layout(title, content, user, msg);

// ====== ROUTES ======
app.get("/", (req, res) => {
  const user = req.session.user;
  const body = `
    <div class="card">
      <h2>Welcome</h2>
      <p>Two roles:</p>
      <ul>
        <li><b>Technician</b>: upload scans → <a href="/upload">Upload Page</a></li>
        <li><b>Dentist</b>: view scans → <a href="/scans">Scan Viewer</a></li>
      </ul>
      <hr/>
      <p class="meta">Demo logins:</p>
      <table class="table">
        <tr><th>Role</th><th>Email</th><th>Password</th></tr>
        <tr><td>Technician</td><td>tech@oralvis.com</td><td>tech123</td></tr>
        <tr><td>Dentist</td><td>dentist@oralvis.com</td><td>dent123</td></tr>
      </table>
    </div>
  `;
  res.send(htmlPage("Home", body, user));
});

app.get("/login", (req, res) => {
  const msg = req.query.msg ? decodeURIComponent(req.query.msg) : "";
  const body = `
    <div class="card">
      <h2>Login</h2>
      <form method="post" action="/login">
        <label>Email</label>
        <input type="email" name="email" required placeholder="you@oralvis.com" />
        <label>Password</label>
        <input type="password" name="password" required placeholder="••••••••" />
        <div style="margin-top:14px; display:flex; gap:10px;">
          <button type="submit">Login</button>
          <a href="/" class="btn-secondary"><button class="btn-secondary" type="button">Cancel</button></a>
        </div>
      </form>
      <hr/>
      <p class="meta">Use demo accounts shown on the home page.</p>
    </div>
  `;
  res.send(htmlPage("Login", body, null, msg));
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) return res.redirect("/login?msg=Invalid%20credentials");
    if (!bcrypt.compareSync(password, user.password_hash))
      return res.redirect("/login?msg=Invalid%20credentials");
    req.session.user = { id: user.id, email: user.email, role: user.role };
    if (user.role === "Technician") return res.redirect("/upload");
    return res.redirect("/scans");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login?msg=Logged%20out"));
});

// ====== TECHNICIAN: UPLOAD ======
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

app.get("/upload", requireRole("Technician"), (req, res) => {
  const body = `
    <div class="card">
      <h2>Upload Scan</h2>
      <form method="post" action="/upload" enctype="multipart/form-data">
        <div class="row">
          <div>
            <label>Patient Name</label>
            <input name="patient_name" required placeholder="Jane Doe"/>
          </div>
          <div>
            <label>Patient ID</label>
            <input name="patient_id" required placeholder="PID-001"/>
          </div>
        </div>
        <div class="row">
          <div>
            <label>Scan Type</label>
            <select name="scan_type" required>
              <option value="RGB">RGB</option>
            </select>
          </div>
          <div>
            <label>Region</label>
            <select name="region" required>
              <option>Frontal</option>
              <option>Upper Arch</option>
              <option>Lower Arch</option>
            </select>
          </div>
        </div>
        <label>Upload Scan Image (JPG/PNG)</label>
        <input type="file" name="scanImage" accept="image/jpeg,image/png" required />
        <div style="margin-top:14px;">
          <button type="submit">Upload</button>
          <a href="/"><button class="btn-secondary" type="button">Home</button></a>
        </div>
      </form>
    </div>
  `;
  res.send(htmlPage("Upload Scan", body, req.session.user));
});

app.post("/upload", requireRole("Technician"), upload.single("scanImage"), async (req, res) => {
  try {
    const { patient_name, patient_id, scan_type, region } = req.body;
    if (!req.file) throw new Error("No file upload detected.");

    // Upload to Cloudinary
    const streamUpload = () =>
      new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "oralvis-scans", resource_type: "image" },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        streamifier.createReadStream(req.file.buffer).pipe(stream);
      });
    const result = await streamUpload();

    // Save to DB
    const uploaded_at = new Date().toISOString();
    db.run(
      `INSERT INTO scans (patient_name, patient_id, scan_type, region, image_url, uploaded_at, technician_email)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [patient_name, patient_id, scan_type, region, result.secure_url, uploaded_at, req.session.user.email],
      function (err) {
        if (err) {
          console.error("DB insert error:", err);
          return res.send(htmlPage("Upload Error", `<p class="error">Failed to save scan.</p>`, req.session.user));
        }
        res.redirect("/upload?msg=" + encodeURIComponent("Scan uploaded successfully (ID " + this.lastID + ")"));
      }
    );
  } catch (e) {
    console.error(e);
    res.send(htmlPage("Upload Error", `<p class="error">${e.message}</p>`, req.session.user));
  }
});

// ====== DENTIST: VIEWER ======
app.get("/scans", requireRole("Dentist"), (req, res) => {
  db.all(`SELECT * FROM scans ORDER BY datetime(uploaded_at) DESC`, [], (err, rows) => {
    if (err) return res.send(htmlPage("Error", `<p class="error">Failed to fetch scans.</p>`, req.session.user));
    const cards = rows
      .map(
        (r) => `
      <div class="card">
        <img class="thumb" src="${r.image_url}" alt="Scan ${r.id}"/>
        <div style="margin-top:8px;">
          <div><b>${r.patient_name}</b> <span class="meta">(${r.patient_id})</span></div>
          <div class="meta">${r.scan_type} · ${r.region}</div>
          <div class="meta">Uploaded: ${new Date(r.uploaded_at).toLocaleString()}</div>
        </div>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <a href="/image/${r.id}"><button class="btn-secondary">View Full Image</button></a>
          <a href="/scans/${r.id}/pdf"><button>Download PDF</button></a>
        </div>
      </div>
    `
      )
      .join("");
    const body = `
      <div class="card">
        <h2>Scan Viewer</h2>
        ${rows.length === 0 ? `<p class="meta">No scans yet.</p>` : ""}
        <div class="grid">${cards}</div>
      </div>
    `;
    res.send(htmlPage("Scans", body, req.session.user));
  });
});

// Full Image page (for Dentists)
app.get("/image/:id", requireRole("Dentist"), (req, res) => {
  db.get(`SELECT * FROM scans WHERE id = ?`, [req.params.id], (err, r) => {
    if (err || !r) return res.status(404).send(htmlPage("Not found", `<p class="error">Scan not found.</p>`, req.session.user));
    const body = `
      <div class="card">
        <h2>Full Image</h2>
        <div class="meta">${r.patient_name} (${r.patient_id}) · ${r.scan_type} · ${r.region} · ${new Date(r.uploaded_at).toLocaleString()}</div>
        <img src="${r.image_url}" alt="Scan ${r.id}" style="width:100%; max-height:75vh; object-fit:contain; background:#0a0f1a; margin-top:10px; border:1px solid #1f2937; border-radius:12px;"/>
        <div style="margin-top:12px;">
          <a href="/scans"><button class="btn-secondary">Back to Scans</button></a>
          <a href="/scans/${r.id}/pdf"><button>Download PDF</button></a>
        </div>
      </div>
    `;
    res.send(htmlPage("Full Image", body, req.session.user));
  });
});

// ====== PDF REPORT ======
app.get("/scans/:id/pdf", requireAuth, async (req, res) => {
  db.get(`SELECT * FROM scans WHERE id = ?`, [req.params.id], async (err, r) => {
    if (err || !r) return res.status(404).send("Scan not found.");
    try {
      // fetch image as buffer (pdfkit needs buffer/stream for remote)
      const imgResp = await axios.get(r.image_url, { responseType: "arraybuffer" });
      const imgBuf = Buffer.from(imgResp.data);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename=scan_${r.id}.pdf`);

      const doc = new PDFDocument({ autoFirstPage: false });
      doc.pipe(res);

      // Cover
      doc.addPage({ size: "A4", margins: { top: 50, left: 60, right: 60, bottom: 60 } });
      doc.fontSize(20).text("OralVis Healthcare – Scan Report", { align: "left" }).moveDown(0.5);
      doc.fontSize(12).fillColor("#555").text(new Date().toLocaleString());
      doc.moveDown(1);

      // Meta table
      const meta = [
        ["Patient Name", r.patient_name],
        ["Patient ID", r.patient_id],
        ["Scan Type", r.scan_type],
        ["Region", r.region],
        ["Upload Date", new Date(r.uploaded_at).toLocaleString()],
        ["Uploaded By", r.technician_email],
      ];
      doc.fillColor("#000").fontSize(12);
      meta.forEach(([k, v]) => {
        doc.text(`${k}: `, { continued: true, underline: false, oblique: false, width: 120 });
        doc.font("Helvetica-Bold").text(v);
        doc.font("Helvetica");
      });
      doc.moveDown(1);

      // Image
      try {
        doc.image(imgBuf, { fit: [480, 480], align: "center" });
      } catch {
        doc.fillColor("red").text("Image preview failed to load.");
      }

      doc.end();
    } catch (e) {
      console.error("PDF error:", e.message);
      res.status(500).send("Failed to generate PDF.");
    }
  });
});

// ====== ERROR HANDLER ======
app.use((req, res) => {
  res.status(404).send(htmlPage("404", `<p class="error">Page not found.</p><p><a href="/">Home</a></p>`, req.session.user));
});

// ====== START ======
app.listen(PORT, () => {
  console.log(`OralVis demo running on http://localhost:${PORT}`);
});