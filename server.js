const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const isProduction = process.env.NODE_ENV === "production";
const dbPath = process.env.SQLITE_PATH || path.join(__dirname, "requests.db");
const dbDirectory = path.dirname(dbPath);
if (!fs.existsSync(dbDirectory)) {
  fs.mkdirSync(dbDirectory, { recursive: true });
}
const db = new sqlite3.Database(dbPath);
const allowedStates = new Set(["Open", "Work In Progress", "Pending", "Awaiting Signoff", "Resolved", "Closed"]);
const workerUpdatableStates = new Set(["Work In Progress", "Pending", "Awaiting Signoff"]);
const allowedPriorities = new Set(["Low", "Medium", "High", "Critical"]);
const allowedChannels = new Set(["Phone", "Email", "Walk-In", "Chat"]);
const allowedCategories = new Set(["General", "Access", "Hardware", "Software", "Facilities"]);
const allowedImpacts = new Set(["Low", "Medium", "High"]);
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

function normalizeText(value, maxLength) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, maxLength);
}

function normalizeEmail(value) {
  return normalizeText(value, 254).toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhoneNumber(phoneNumber) {
  return /^\+?[0-9()\-\s]{7,25}$/.test(phoneNumber || "");
}

function isStrongPassword(password) {
  return (
    password.length >= 12
    && /[a-z]/.test(password)
    && /[A-Z]/.test(password)
    && /\d/.test(password)
    && /[^A-Za-z0-9]/.test(password)
  );
}

function isValidSignatureDataUrl(value) {
  return /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(value || "");
}

function safeEqualStrings(left, right) {
  const leftBuffer = Buffer.from(String(left || ""));
  const rightBuffer = Buffer.from(String(right || ""));
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function actorFromRequest(req) {
  if (req.session?.role === "admin") {
    return { role: "admin", identifier: "admin" };
  }
  if (req.session?.workerUsername) {
    return { role: "worker", identifier: req.session.workerUsername };
  }
  return { role: "anonymous", identifier: req.ip || "unknown" };
}

async function addAuditLog(actorRole, actorIdentifier, action, targetType, targetId, metadata = {}) {
  const safeMetadata = JSON.stringify(metadata).slice(0, 4000);
  await runSql(
    `
      INSERT INTO audit_logs (actor_role, actor_identifier, action, target_type, target_id, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      normalizeText(actorRole, 20),
      normalizeText(actorIdentifier, 120),
      normalizeText(action, 80),
      normalizeText(targetType || "system", 40),
      normalizeText(String(targetId || ""), 120),
      safeMetadata,
      new Date().toISOString(),
    ]
  );
}

async function addRequestAudit(req, action, targetType, targetId, metadata = {}) {
  const actor = actorFromRequest(req);
  await addAuditLog(actor.role, actor.identifier, action, targetType, targetId, {
    ...metadata,
    ip: req.ip,
  });
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function destroySession(req) {
  return new Promise((resolve) => {
    req.session.destroy(() => {
      resolve();
    });
  });
}

function runSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve(this);
    });
  });
}

function getSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

function allSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows);
    });
  });
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
}

function generateSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function createPasswordRecord(password) {
  const passwordSalt = generateSalt();
  const passwordHash = hashPassword(password, passwordSalt);
  return { passwordSalt, passwordHash };
}

function verifyPassword(password, passwordSalt, passwordHash) {
  const computed = hashPassword(password, passwordSalt);
  return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(passwordHash, "hex"));
}

function ticketKeyFromId(id) {
  return `REQ-${String(id).padStart(5, "0")}`;
}

async function addNotification(requestId, message) {
  await runSql(
    `
      INSERT INTO notifications (request_id, message, created_at)
      VALUES (?, ?, ?)
    `,
    [requestId, message, new Date().toISOString()]
  );
}

function requireAdmin(req, res, next) {
  if (req.session?.role !== "admin") {
    res.status(401).json({ error: "Admin authentication required." });
    return;
  }
  next();
}

function requireWorker(req, res, next) {
  if (req.session?.role !== "worker" || !req.session?.workerUsername) {
    res.status(401).json({ error: "Worker authentication required." });
    return;
  }
  next();
}

function calculateHoursBetween(startIso, endIso) {
  const start = new Date(startIso).getTime();
  const end = new Date(endIso).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
    return 0;
  }
  return (end - start) / (1000 * 60 * 60);
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_key TEXT UNIQUE,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      department TEXT NOT NULL,
      priority TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'Phone',
      contact_phone TEXT,
      category TEXT NOT NULL DEFAULT 'General',
      impact TEXT NOT NULL DEFAULT 'Medium',
      details TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Open',
      assigned_department TEXT,
      assigned_user TEXT,
      assigned_at TEXT,
      resolved_at TEXT,
      total_time_spent_minutes INTEGER NOT NULL DEFAULT 0,
      requester_signed_off INTEGER NOT NULL DEFAULT 0,
      requester_signature TEXT,
      requester_signed_off_name TEXT,
      requester_signed_off_at TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  const requestMigrations = [
    "ALTER TABLE requests ADD COLUMN ticket_key TEXT",
    "ALTER TABLE requests ADD COLUMN status TEXT DEFAULT 'Open'",
    "ALTER TABLE requests ADD COLUMN assigned_department TEXT",
    "ALTER TABLE requests ADD COLUMN assigned_user TEXT",
    "ALTER TABLE requests ADD COLUMN assigned_at TEXT",
    "ALTER TABLE requests ADD COLUMN resolved_at TEXT",
    "ALTER TABLE requests ADD COLUMN total_time_spent_minutes INTEGER DEFAULT 0",
    "ALTER TABLE requests ADD COLUMN requester_signed_off INTEGER DEFAULT 0",
    "ALTER TABLE requests ADD COLUMN requester_signature TEXT",
    "ALTER TABLE requests ADD COLUMN requester_signed_off_name TEXT",
    "ALTER TABLE requests ADD COLUMN requester_signed_off_at TEXT",
    "ALTER TABLE requests ADD COLUMN updated_at TEXT",
    "ALTER TABLE requests ADD COLUMN channel TEXT DEFAULT 'Phone'",
    "ALTER TABLE requests ADD COLUMN contact_phone TEXT",
    "ALTER TABLE requests ADD COLUMN category TEXT DEFAULT 'General'",
    "ALTER TABLE requests ADD COLUMN impact TEXT DEFAULT 'Medium'",
  ];

  requestMigrations.forEach((statement) => {
    db.run(statement, () => {});
  });

  db.run("UPDATE requests SET status = 'Open' WHERE status IS NULL");
  db.run("UPDATE requests SET requester_signed_off = 0 WHERE requester_signed_off IS NULL");
  db.run("UPDATE requests SET total_time_spent_minutes = 0 WHERE total_time_spent_minutes IS NULL");
  db.run("UPDATE requests SET updated_at = created_at WHERE updated_at IS NULL");
  db.run("UPDATE requests SET channel = 'Phone' WHERE channel IS NULL");
  db.run("UPDATE requests SET category = 'General' WHERE category IS NULL");
  db.run("UPDATE requests SET impact = 'Medium' WHERE impact IS NULL");

  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (request_id) REFERENCES requests(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS worker_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      department TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      must_change_password INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_role TEXT NOT NULL,
      actor_identifier TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      metadata TEXT,
      created_at TEXT NOT NULL
    )
  `);

  const workerMigrations = [
    "ALTER TABLE worker_accounts ADD COLUMN is_active INTEGER DEFAULT 1",
    "ALTER TABLE worker_accounts ADD COLUMN failed_attempts INTEGER DEFAULT 0",
    "ALTER TABLE worker_accounts ADD COLUMN locked_until TEXT",
    "ALTER TABLE worker_accounts ADD COLUMN must_change_password INTEGER DEFAULT 1",
    "ALTER TABLE worker_accounts ADD COLUMN created_at TEXT",
  ];

  workerMigrations.forEach((statement) => {
    db.run(statement, () => {});
  });

  db.run("UPDATE worker_accounts SET is_active = 1 WHERE is_active IS NULL");
  db.run("UPDATE worker_accounts SET failed_attempts = 0 WHERE failed_attempts IS NULL");
  db.run("UPDATE worker_accounts SET must_change_password = 1 WHERE must_change_password IS NULL");
  db.run("UPDATE worker_accounts SET created_at = datetime('now') WHERE created_at IS NULL");

  const defaultWorkers = [
    { fullName: "Alex Smith", username: "alex.smith", department: "IT", password: "Temp#1234" },
    { fullName: "Jordan Lee", username: "jordan.lee", department: "IT", password: "Temp#1234" },
    { fullName: "Morgan Reed", username: "morgan.reed", department: "HR", password: "Temp#1234" },
    { fullName: "Taylor Brown", username: "taylor.brown", department: "HR", password: "Temp#1234" },
    { fullName: "Casey Patel", username: "casey.patel", department: "Facilities", password: "Temp#1234" },
    { fullName: "Riley Kim", username: "riley.kim", department: "Facilities", password: "Temp#1234" },
  ];

  defaultWorkers.forEach((worker) => {
    const { passwordSalt, passwordHash } = createPasswordRecord(worker.password);
    db.run(
      `
        INSERT OR IGNORE INTO worker_accounts (full_name, username, department, password_hash, password_salt, is_active, failed_attempts, locked_until, must_change_password, created_at)
        VALUES (?, ?, ?, ?, ?, 1, 0, NULL, 1, ?)
      `,
      [worker.fullName, worker.username, worker.department, passwordHash, passwordSalt, new Date().toISOString()]
    );
  });

  db.all("SELECT id FROM requests WHERE ticket_key IS NULL OR ticket_key = ''", (error, rows) => {
    if (error || !rows) {
      return;
    }
    rows.forEach((row) => {
      const key = ticketKeyFromId(row.id);
      db.run("UPDATE requests SET ticket_key = ? WHERE id = ?", [key, row.id]);
    });
  });
});

if (!process.env.SESSION_SECRET) {
  console.warn("SESSION_SECRET is not set. Set a strong secret in production.");
}

app.disable("x-powered-by");
if (isProduction) {
  app.set("trust proxy", 1);
}

app.use(
  helmet({
    referrerPolicy: { policy: "no-referrer" },
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please wait and try again." },
});

app.use(express.json({ limit: "100kb" }));
app.use(
  session({
    name: "sd.sid",
    secret: process.env.SESSION_SECRET || "change-this-session-secret",
    resave: false,
    saveUninitialized: false,
    unset: "destroy",
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);
app.use("/api", apiLimiter);
app.use("/api/admin/login", authLimiter);
app.use("/api/worker/login", authLimiter);
app.use(express.static(__dirname));

app.post("/api/requests", async (req, res) => {
  const {
    name,
    email,
    department,
    priority,
    details,
    channel,
    phoneNumber,
    category,
    impact,
  } = req.body;

  const cleanName = normalizeText(name, 120);
  const cleanEmail = normalizeEmail(email);
  const cleanDepartment = normalizeText(department, 80);
  const cleanPriority = normalizeText(priority, 20);
  const cleanChannel = normalizeText(channel || "Phone", 20);
  const cleanPhoneNumber = normalizeText(phoneNumber, 25);
  const cleanCategory = normalizeText(category || "General", 30);
  const cleanImpact = normalizeText(impact || "Medium", 20);
  const cleanDetails = normalizeText(details, 5000);

  if (!cleanName || !cleanEmail || !cleanDepartment || !cleanPriority || !cleanDetails) {
    res.status(400).json({ error: "All required fields must be completed." });
    return;
  }

  if (!isValidEmail(cleanEmail)) {
    res.status(400).json({ error: "A valid email address is required." });
    return;
  }

  if (!allowedPriorities.has(cleanPriority) || !allowedChannels.has(cleanChannel)
    || !allowedCategories.has(cleanCategory) || !allowedImpacts.has(cleanImpact)) {
    res.status(400).json({ error: "One or more request fields are invalid." });
    return;
  }

  if (cleanChannel === "Phone" && !cleanPhoneNumber) {
    res.status(400).json({ error: "Phone number is required when contact channel is Phone." });
    return;
  }

  if (cleanPhoneNumber && !isValidPhoneNumber(cleanPhoneNumber)) {
    res.status(400).json({ error: "Phone number format is invalid." });
    return;
  }

  try {
    const timestamp = new Date().toISOString();
    const insertResult = await runSql(
      `
        INSERT INTO requests (
          name, email, department, priority, channel, contact_phone, category, impact,
          details, status, requester_signed_off, updated_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', 0, ?, ?)
      `,
      [
        cleanName,
        cleanEmail,
        cleanDepartment,
        cleanPriority,
        cleanChannel,
        cleanPhoneNumber || null,
        cleanCategory,
        cleanImpact,
        cleanDetails,
        timestamp,
        timestamp,
      ]
    );

    const ticketKey = ticketKeyFromId(insertResult.lastID);
    await runSql("UPDATE requests SET ticket_key = ? WHERE id = ?", [ticketKey, insertResult.lastID]);

    await addNotification(insertResult.lastID, "Request created and awaiting assignment.");
    await addRequestAudit(req, "request_created", "request", insertResult.lastID, { ticketKey });

    res.status(201).json({
      id: insertResult.lastID,
      ticketKey,
      status: "Open",
      createdAt: timestamp,
    });
  } catch {
    res.status(500).json({ error: "Failed to save request." });
  }
});

app.get("/api/requests/lookup/ref", async (req, res) => {
  const reference = String(req.query.reference || "").trim().toUpperCase();
  const email = normalizeEmail(req.query.email);

  if (!reference || !email) {
    res.status(400).json({ error: "Reference and email are required." });
    return;
  }

  if (!isValidEmail(email) || reference.length > 20) {
    res.status(400).json({ error: "Reference or email format is invalid." });
    return;
  }

  try {
    let row;
    if (/^\d+$/.test(reference)) {
      row = await getSql("SELECT id FROM requests WHERE id = ? AND lower(email) = ?", [Number(reference), email]);
    } else {
      row = await getSql("SELECT id FROM requests WHERE upper(ticket_key) = ? AND lower(email) = ?", [reference, email]);
    }

    if (!row) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    res.json({ id: row.id });
  } catch {
    res.status(500).json({ error: "Failed to find request." });
  }
});

app.get("/api/requests/:id", async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const email = normalizeEmail(req.query.email);

  if (!Number.isInteger(requestId) || requestId <= 0 || !email) {
    res.status(400).json({ error: "Request ID and email are required." });
    return;
  }

  if (!isValidEmail(email)) {
    res.status(400).json({ error: "A valid email address is required." });
    return;
  }

  try {
    const requestRow = await getSql(
      `
        SELECT
          r.id,
          r.ticket_key as ticketKey,
          r.name,
          r.email,
          r.department,
          r.priority,
          r.channel,
          r.contact_phone as contactPhone,
          r.category,
          r.impact,
          r.details,
          r.status,
          r.assigned_department as assignedDepartment,
          COALESCE(w.full_name, r.assigned_user) as assignedUser,
          r.total_time_spent_minutes as totalTimeSpentMinutes,
          r.requester_signed_off as requesterSignedOff,
          r.requester_signed_off_name as requesterSignedOffName,
          r.requester_signed_off_at as requesterSignedOffAt,
          CASE WHEN r.requester_signature IS NOT NULL THEN 1 ELSE 0 END as hasSignature,
          r.updated_at as updatedAt,
          r.created_at as createdAt
        FROM requests r
        LEFT JOIN worker_accounts w ON r.assigned_user = w.username
        WHERE r.id = ? AND lower(r.email) = ?
      `,
      [requestId, email]
    );

    if (!requestRow) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    const notifications = await allSql(
      `
        SELECT id, message, created_at as createdAt
        FROM notifications
        WHERE request_id = ?
        ORDER BY datetime(created_at) DESC
      `,
      [requestId]
    );

    res.json({
      request: requestRow,
      notifications,
    });
  } catch {
    res.status(500).json({ error: "Failed to load request." });
  }
});

app.post("/api/requests/:id/signoff", async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const email = normalizeEmail(req.body.email);
  const signatureDataUrl = String(req.body.signatureDataUrl || "").trim();
  const signerName = normalizeText(req.body.signerName, 120);

  if (!Number.isInteger(requestId) || requestId <= 0 || !email || !signatureDataUrl || !signerName) {
    res.status(400).json({ error: "Request ID and email are required." });
    return;
  }

  if (!isValidEmail(email)) {
    res.status(400).json({ error: "A valid email address is required." });
    return;
  }

  if (!isValidSignatureDataUrl(signatureDataUrl) || signatureDataUrl.length > 300000) {
    res.status(400).json({ error: "A valid drawn signature is required." });
    return;
  }

  try {
    const requestRow = await getSql("SELECT id, status FROM requests WHERE id = ? AND lower(email) = ?", [requestId, email]);

    if (!requestRow) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    if (requestRow.status !== "Awaiting Signoff") {
      res.status(400).json({ error: "This request is not ready for requester signoff yet." });
      return;
    }

    const timestamp = new Date().toISOString();
    await runSql(
      `
        UPDATE requests
        SET status = 'Resolved', requester_signed_off = 1,
            requester_signature = ?, requester_signed_off_name = ?, requester_signed_off_at = ?,
            resolved_at = ?, updated_at = ?
        WHERE id = ?
      `,
      [signatureDataUrl, signerName, timestamp, timestamp, timestamp, requestId]
    );

    await addNotification(requestId, `Requester signed off by ${signerName}. Request is now Resolved.`);
    await addRequestAudit(req, "request_signed_off", "request", requestId);
    res.status(200).json({ ok: true, status: "Resolved" });
  } catch {
    res.status(500).json({ error: "Failed to sign off request." });
  }
});

app.post("/api/requests/:id/dispute", async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const email = normalizeEmail(req.body.email);
  const reason = normalizeText(req.body.reason, 1000);

  if (!Number.isInteger(requestId) || requestId <= 0 || !email || !reason) {
    res.status(400).json({ error: "Request ID, email, and dispute reason are required." });
    return;
  }

  if (!isValidEmail(email)) {
    res.status(400).json({ error: "A valid email address is required." });
    return;
  }

  try {
    const requestRow = await getSql(
      "SELECT id, status FROM requests WHERE id = ? AND lower(email) = ?",
      [requestId, email]
    );

    if (!requestRow) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    if (requestRow.status !== "Resolved") {
      res.status(400).json({ error: "Only resolved requests can be disputed." });
      return;
    }

    const timestamp = new Date().toISOString();
    await runSql(
      `
        UPDATE requests
        SET status = 'Work In Progress', requester_signed_off = 0,
            requester_signature = NULL, requester_signed_off_name = NULL,
            requester_signed_off_at = NULL, resolved_at = NULL, updated_at = ?
        WHERE id = ?
      `,
      [timestamp, requestId]
    );

    await addNotification(requestId, `Requester disputed completion. Request re-opened to Work In Progress. Reason: ${reason}`);
    await addRequestAudit(req, "request_signoff_disputed", "request", requestId, { reason });

    res.json({ ok: true, status: "Work In Progress" });
  } catch {
    res.status(500).json({ error: "Failed to dispute request." });
  }
});

app.post("/api/admin/login", async (req, res) => {
  const password = String(req.body.password || "");

  if (!password || !safeEqualStrings(password, ADMIN_PASSWORD)) {
    await addAuditLog("anonymous", req.ip || "unknown", "admin_login_failed", "auth", "admin", { ip: req.ip });
    res.status(401).json({ error: "Invalid admin password." });
    return;
  }

  try {
    await regenerateSession(req);
    req.session.role = "admin";
    delete req.session.workerUsername;
    delete req.session.workerName;
    await addAuditLog("admin", "admin", "admin_login_success", "auth", "admin", { ip: req.ip });
    res.json({ authenticated: true, role: "admin" });
  } catch {
    res.status(500).json({ error: "Failed to start admin session." });
  }
});

app.post("/api/admin/logout", async (req, res) => {
  await addRequestAudit(req, "admin_logout", "auth", "admin");
  await destroySession(req);
  res.clearCookie("sd.sid");
  res.status(204).end();
});

app.get("/api/admin/session", (req, res) => {
  res.json({ authenticated: req.session?.role === "admin" });
});

app.get("/api/admin/workers", requireAdmin, async (req, res) => {
  try {
    const workers = await allSql(
      `
        SELECT id, full_name as fullName, username, department, is_active as isActive,
               failed_attempts as failedAttempts, locked_until as lockedUntil,
               must_change_password as mustChangePassword, created_at as createdAt
        FROM worker_accounts
        ORDER BY is_active DESC, department, full_name
      `
    );
    res.json(workers);
  } catch {
    res.status(500).json({ error: "Failed to load workers." });
  }
});

app.post("/api/admin/workers", requireAdmin, async (req, res) => {
  const fullName = normalizeText(req.body.fullName, 120);
  const username = normalizeText(req.body.username, 32).toLowerCase();
  const department = normalizeText(req.body.department, 80);
  const password = String(req.body.password || "");

  if (!fullName || !username || !department || !password) {
    res.status(400).json({ error: "fullName, username, department and password are required." });
    return;
  }

  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    res.status(400).json({ error: "Username must be 3-32 chars and use a-z, 0-9, ., _, -." });
    return;
  }

  if (!isStrongPassword(password)) {
    res.status(400).json({ error: "Password must be 12+ chars and include upper, lower, number, and symbol." });
    return;
  }

  try {
    const existing = await getSql("SELECT id FROM worker_accounts WHERE username = ?", [username]);
    if (existing) {
      res.status(409).json({ error: "Username already exists." });
      return;
    }

    const { passwordSalt, passwordHash } = createPasswordRecord(password);
    await runSql(
      `
        INSERT INTO worker_accounts (full_name, username, department, password_hash, password_salt, is_active, failed_attempts, locked_until, must_change_password, created_at)
        VALUES (?, ?, ?, ?, ?, 1, 0, NULL, 1, ?)
      `,
      [fullName, username, department, passwordHash, passwordSalt, new Date().toISOString()]
    );

    await addRequestAudit(req, "worker_created", "worker", username, { department });

    res.status(201).json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to create worker." });
  }
});

app.delete("/api/admin/workers/:id", requireAdmin, async (req, res) => {
  const workerId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(workerId) || workerId <= 0) {
    res.status(400).json({ error: "Valid worker ID is required." });
    return;
  }

  try {
    const worker = await getSql("SELECT username FROM worker_accounts WHERE id = ?", [workerId]);
    if (!worker) {
      res.status(404).json({ error: "Worker not found." });
      return;
    }

    await runSql("UPDATE worker_accounts SET is_active = 0 WHERE id = ?", [workerId]);
    await addRequestAudit(req, "worker_deactivated", "worker", worker.username);
    res.status(204).end();
  } catch {
    res.status(500).json({ error: "Failed to deactivate worker." });
  }
});

app.delete("/api/admin/workers/:id/permanent", requireAdmin, async (req, res) => {
  const workerId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(workerId) || workerId <= 0) {
    res.status(400).json({ error: "Valid worker ID is required." });
    return;
  }

  try {
    const worker = await getSql(
      "SELECT username, full_name as fullName FROM worker_accounts WHERE id = ?",
      [workerId]
    );
    if (!worker) {
      res.status(404).json({ error: "Worker not found." });
      return;
    }

    const activeAssignments = await getSql(
      `
        SELECT COUNT(1) as activeCount
        FROM requests
        WHERE (assigned_user = ? OR assigned_user = ?)
          AND status NOT IN ('Resolved', 'Closed')
      `,
      [worker.username, worker.fullName]
    );

    if (Number(activeAssignments?.activeCount || 0) > 0) {
      res.status(409).json({ error: "Reassign this worker's open tickets before removing them." });
      return;
    }

    await runSql("DELETE FROM worker_accounts WHERE id = ?", [workerId]);
    await addRequestAudit(req, "worker_removed", "worker", worker.username);
    res.status(204).end();
  } catch {
    res.status(500).json({ error: "Failed to remove worker." });
  }
});

app.get("/api/admin/departments", requireAdmin, async (req, res) => {
  try {
    const rows = await allSql(
      `
        SELECT id, department, full_name as fullName, username
        FROM worker_accounts
        WHERE is_active = 1
        ORDER BY department, full_name
      `
    );

    const grouped = rows.reduce((accumulator, row) => {
      if (!accumulator[row.department]) {
        accumulator[row.department] = [];
      }
      accumulator[row.department].push({
        id: row.id,
        fullName: row.fullName,
        username: row.username,
      });
      return accumulator;
    }, {});

    res.json(grouped);
  } catch {
    res.status(500).json({ error: "Failed to load departments." });
  }
});

app.get("/api/admin/requests", requireAdmin, async (req, res) => {
  try {
    const rows = await allSql(
      `
        SELECT
          r.id,
          r.ticket_key as ticketKey,
          r.name,
          r.email,
          r.department,
          r.priority,
          r.channel,
          r.contact_phone as contactPhone,
          r.category,
          r.impact,
          r.details,
          r.status,
          r.assigned_department as assignedDepartment,
          r.assigned_user as assignedUser,
          COALESCE(w.full_name, r.assigned_user) as assignedUserName,
          r.assigned_at as assignedAt,
          r.resolved_at as resolvedAt,
          r.total_time_spent_minutes as totalTimeSpentMinutes,
          r.requester_signed_off as requesterSignedOff,
          r.requester_signed_off_name as requesterSignedOffName,
          r.requester_signed_off_at as requesterSignedOffAt,
          CASE WHEN r.requester_signature IS NOT NULL THEN 1 ELSE 0 END as hasSignature,
          r.updated_at as updatedAt,
          r.created_at as createdAt
        FROM requests r
        LEFT JOIN worker_accounts w ON r.assigned_user = w.username
        ORDER BY datetime(r.created_at) DESC
      `
    );
    res.json(rows);
  } catch {
    res.status(500).json({ error: "Failed to load requests." });
  }
});

app.get("/api/admin/requests/:id/signature", requireAdmin, async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(requestId) || requestId <= 0) {
    res.status(400).json({ error: "Valid request ID is required." });
    return;
  }

  try {
    const row = await getSql(
      `
        SELECT
          id,
          ticket_key as ticketKey,
          requester_signature as signatureDataUrl,
          requester_signed_off_name as signerName,
          requester_signed_off_at as signedAt
        FROM requests
        WHERE id = ?
      `,
      [requestId]
    );

    if (!row) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    if (!row.signatureDataUrl) {
      res.status(404).json({ error: "No signature is available for this request." });
      return;
    }

    await addRequestAudit(req, "signature_viewed", "request", requestId);
    res.json(row);
  } catch {
    res.status(500).json({ error: "Failed to load signature." });
  }
});

app.get("/api/admin/metrics", requireAdmin, async (req, res) => {
  try {
    const requests = await allSql(
      `
        SELECT
          id,
          status,
          created_at as createdAt,
          assigned_at as assignedAt,
          resolved_at as resolvedAt,
          updated_at as updatedAt
        FROM requests
      `
    );

    const stateCounts = {
      Open: 0,
      "Work In Progress": 0,
      Pending: 0,
      "Awaiting Signoff": 0,
      Resolved: 0,
      Closed: 0,
    };

    let totalResolutionHours = 0;
    let resolvedCount = 0;
    let totalAssignmentMinutes = 0;
    let assignedCount = 0;

    requests.forEach((request) => {
      if (Object.prototype.hasOwnProperty.call(stateCounts, request.status)) {
        stateCounts[request.status] += 1;
      }

      if (request.resolvedAt) {
        totalResolutionHours += calculateHoursBetween(request.createdAt, request.resolvedAt);
        resolvedCount += 1;
      }

      if (request.assignedAt) {
        totalAssignmentMinutes += calculateHoursBetween(request.createdAt, request.assignedAt) * 60;
        assignedCount += 1;
      }
    });

    res.json({
      total: requests.length,
      stateCounts,
      avgResolutionHours: resolvedCount ? Number((totalResolutionHours / resolvedCount).toFixed(2)) : 0,
      avgAssignmentMinutes: assignedCount ? Number((totalAssignmentMinutes / assignedCount).toFixed(1)) : 0,
    });
  } catch {
    res.status(500).json({ error: "Failed to load metrics." });
  }
});

app.post("/api/admin/requests/:id/assign", requireAdmin, async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const department = normalizeText(req.body.department, 80);
  const assigneeUsername = normalizeText(req.body.assigneeUsername, 32).toLowerCase();

  if (!Number.isInteger(requestId) || requestId <= 0 || !assigneeUsername) {
    res.status(400).json({ error: "Request ID and assigneeUsername are required." });
    return;
  }

  try {
    const worker = await getSql(
      "SELECT username, full_name as fullName, department FROM worker_accounts WHERE username = ? AND is_active = 1",
      [assigneeUsername]
    );

    if (!worker) {
      res.status(400).json({ error: "Assignee must be an active worker." });
      return;
    }

    const requestExists = await getSql("SELECT id FROM requests WHERE id = ?", [requestId]);
    if (!requestExists) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    const assignedDepartment = worker.department;
    const timestamp = new Date().toISOString();
    await runSql(
      `
        UPDATE requests
        SET assigned_department = ?, assigned_user = ?, status = 'Work In Progress', requester_signed_off = 0,
            requester_signature = NULL, requester_signed_off_name = NULL, requester_signed_off_at = NULL,
            resolved_at = NULL, assigned_at = COALESCE(assigned_at, ?), updated_at = ?
        WHERE id = ?
      `,
      [assignedDepartment, assigneeUsername, timestamp, timestamp, requestId]
    );

    await addNotification(
      requestId,
      `Assigned to ${worker.fullName} (${assignedDepartment}). Status changed to Work In Progress.`
    );
    await addRequestAudit(req, "request_assigned", "request", requestId, {
      department: assignedDepartment,
      requestedDepartment: department || null,
      assignee: worker.username,
    });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to assign request." });
  }
});

app.post("/api/admin/requests/:id/status", requireAdmin, async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const nextStatus = normalizeText(req.body.status, 30);
  const note = normalizeText(req.body.note, 1000);

  if (!Number.isInteger(requestId) || requestId <= 0 || !allowedStates.has(nextStatus)) {
    res.status(400).json({ error: "Valid request ID and status are required." });
    return;
  }

  if (nextStatus === "Open" || nextStatus === "Closed" || nextStatus === "Resolved") {
    res.status(400).json({ error: "Use assignment/signoff flow. Resolved is set only after requester signature." });
    return;
  }

  try {
    const requestRow = await getSql("SELECT assigned_user as assignedUser FROM requests WHERE id = ?", [requestId]);
    if (!requestRow) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    if (!requestRow.assignedUser) {
      res.status(400).json({ error: "Request must be assigned before updating status." });
      return;
    }

    const timestamp = new Date().toISOString();
    if (nextStatus === "Resolved") {
      await runSql(
        "UPDATE requests SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?",
        [nextStatus, timestamp, timestamp, requestId]
      );
    } else {
      await runSql(
        "UPDATE requests SET status = ?, resolved_at = NULL, updated_at = ? WHERE id = ?",
        [nextStatus, timestamp, requestId]
      );
    }

    const message = note
      ? `Status changed to ${nextStatus}. Note: ${note}`
      : `Status changed to ${nextStatus}.`;
    await addNotification(requestId, message);
    await addRequestAudit(req, "request_status_updated_by_admin", "request", requestId, { status: nextStatus });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to update status." });
  }
});

app.post("/api/worker/login", async (req, res) => {
  const username = normalizeText(req.body.username, 32).toLowerCase();
  const password = String(req.body.password || "");

  if (!username || !password) {
    res.status(400).json({ error: "Username and password are required." });
    return;
  }

  try {
    const worker = await getSql(
      `
        SELECT id, username, full_name as fullName, department, password_hash as passwordHash, password_salt as passwordSalt,
               is_active as isActive, failed_attempts as failedAttempts, locked_until as lockedUntil, must_change_password as mustChangePassword
        FROM worker_accounts
        WHERE username = ?
      `,
      [username]
    );

    const now = Date.now();

    if (worker && worker.lockedUntil && new Date(worker.lockedUntil).getTime() > now) {
      await addAuditLog("worker", username, "worker_login_blocked_locked", "auth", username, { ip: req.ip });
      res.status(423).json({ error: "Account is temporarily locked. Please try again later." });
      return;
    }

    if (!worker || !worker.isActive || !verifyPassword(password, worker.passwordSalt, worker.passwordHash)) {
      if (worker && worker.isActive) {
        const attempts = Number(worker.failedAttempts || 0) + 1;
        if (attempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
          const lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString();
          await runSql("UPDATE worker_accounts SET failed_attempts = 0, locked_until = ? WHERE id = ?", [lockedUntil, worker.id]);
          await addAuditLog("worker", username, "worker_login_locked", "auth", username, { ip: req.ip, lockedUntil });
          res.status(423).json({ error: "Account locked due to repeated failed login attempts." });
          return;
        }
        await runSql("UPDATE worker_accounts SET failed_attempts = ? WHERE id = ?", [attempts, worker.id]);
      }
      await addAuditLog("worker", username || "unknown", "worker_login_failed", "auth", username || "unknown", { ip: req.ip });
      res.status(401).json({ error: "Invalid worker credentials." });
      return;
    }

    await runSql("UPDATE worker_accounts SET failed_attempts = 0, locked_until = NULL WHERE id = ?", [worker.id]);

    await regenerateSession(req);
    req.session.role = worker.mustChangePassword ? "worker-reset" : "worker";
    req.session.workerUsername = worker.username;
    req.session.workerName = worker.fullName;
    await addAuditLog("worker", worker.username, "worker_login_success", "auth", worker.username, { ip: req.ip, mustChangePassword: Boolean(worker.mustChangePassword) });

    res.json({
      authenticated: true,
      username: worker.username,
      fullName: worker.fullName,
      department: worker.department,
      requirePasswordChange: Boolean(worker.mustChangePassword),
    });
  } catch {
    res.status(500).json({ error: "Failed to authenticate worker." });
  }
});

app.post("/api/worker/change-password", async (req, res) => {
  if (!["worker", "worker-reset"].includes(req.session?.role) || !req.session?.workerUsername) {
    res.status(401).json({ error: "Worker authentication required." });
    return;
  }

  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");

  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: "Current and new password are required." });
    return;
  }

  if (!isStrongPassword(newPassword)) {
    res.status(400).json({ error: "New password must be 12+ chars and include upper, lower, number, and symbol." });
    return;
  }

  try {
    const worker = await getSql(
      "SELECT id, username, password_hash as passwordHash, password_salt as passwordSalt FROM worker_accounts WHERE username = ? AND is_active = 1",
      [req.session.workerUsername]
    );

    if (!worker || !verifyPassword(currentPassword, worker.passwordSalt, worker.passwordHash)) {
      await addAuditLog("worker", req.session.workerUsername, "worker_password_change_failed", "worker", req.session.workerUsername, { reason: "invalid_current_password", ip: req.ip });
      res.status(400).json({ error: "Current password is incorrect." });
      return;
    }

    if (safeEqualStrings(currentPassword, newPassword)) {
      res.status(400).json({ error: "New password must be different from current password." });
      return;
    }

    const { passwordSalt, passwordHash } = createPasswordRecord(newPassword);
    await runSql(
      "UPDATE worker_accounts SET password_hash = ?, password_salt = ?, must_change_password = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?",
      [passwordHash, passwordSalt, worker.id]
    );

    req.session.role = "worker";
    await addAuditLog("worker", req.session.workerUsername, "worker_password_changed", "worker", req.session.workerUsername, { ip: req.ip });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to change password." });
  }
});

app.post("/api/worker/logout", async (req, res) => {
  await addRequestAudit(req, "worker_logout", "auth", req.session?.workerUsername || "worker");
  await destroySession(req);
  res.clearCookie("sd.sid");
  res.status(204).end();
});

app.get("/api/worker/session", (req, res) => {
  if (!["worker", "worker-reset"].includes(req.session?.role)) {
    res.json({ authenticated: false });
    return;
  }

  res.json({
    authenticated: true,
    requirePasswordChange: req.session.role === "worker-reset",
    username: req.session.workerUsername,
    fullName: req.session.workerName,
  });
});

app.get("/api/worker/requests", requireWorker, async (req, res) => {
  try {
    const worker = await getSql("SELECT full_name as fullName FROM worker_accounts WHERE username = ?", [req.session.workerUsername]);
    const fullName = worker?.fullName || "";

    const rows = await allSql(
      `
        SELECT
          r.id,
          r.ticket_key as ticketKey,
          r.name,
          r.email,
          r.department,
          r.priority,
          r.channel,
          r.contact_phone as contactPhone,
          r.category,
          r.impact,
          r.details,
          r.status,
          r.assigned_department as assignedDepartment,
          r.assigned_user as assignedUser,
          r.total_time_spent_minutes as totalTimeSpentMinutes,
          r.updated_at as updatedAt,
          r.created_at as createdAt
        FROM requests r
        WHERE r.assigned_user = ? OR r.assigned_user = ?
        ORDER BY datetime(r.updated_at) DESC
      `,
      [req.session.workerUsername, fullName]
    );

    res.json(rows);
  } catch {
    res.status(500).json({ error: "Failed to load worker requests." });
  }
});

app.post("/api/worker/requests/:id/status", requireWorker, async (req, res) => {
  const requestId = Number.parseInt(req.params.id, 10);
  const nextStatus = normalizeText(req.body.status, 30);
  const note = normalizeText(req.body.note, 1000);
  const parsedTimeSpentMinutes = Number.parseInt(String(req.body.timeSpentMinutes ?? "0"), 10);
  const timeSpentMinutes = Number.isInteger(parsedTimeSpentMinutes) ? parsedTimeSpentMinutes : 0;

  if (!Number.isInteger(requestId) || requestId <= 0 || !workerUpdatableStates.has(nextStatus)) {
    res.status(400).json({ error: "Valid request ID and worker status are required." });
    return;
  }

  if (timeSpentMinutes < 0 || timeSpentMinutes > 1440) {
    res.status(400).json({ error: "Time spent must be between 0 and 1440 minutes." });
    return;
  }

  try {
    const worker = await getSql("SELECT full_name as fullName FROM worker_accounts WHERE username = ?", [req.session.workerUsername]);
    const fullName = worker?.fullName || "";

    const requestRow = await getSql(
      "SELECT id, assigned_user as assignedUser FROM requests WHERE id = ?",
      [requestId]
    );

    if (!requestRow) {
      res.status(404).json({ error: "Request not found." });
      return;
    }

    if (requestRow.assignedUser !== req.session.workerUsername && requestRow.assignedUser !== fullName) {
      res.status(403).json({ error: "You can only update requests assigned to you." });
      return;
    }

    const timestamp = new Date().toISOString();
    await runSql(
      "UPDATE requests SET status = ?, resolved_at = NULL, total_time_spent_minutes = COALESCE(total_time_spent_minutes, 0) + ?, updated_at = ? WHERE id = ?",
      [nextStatus, timeSpentMinutes, timestamp, requestId]
    );

    const timeMessage = timeSpentMinutes > 0 ? ` Time added: ${timeSpentMinutes} minute(s).` : "";
    const message = note
      ? `${req.session.workerName} set status to ${nextStatus}.${timeMessage} Note: ${note}`
      : `${req.session.workerName} set status to ${nextStatus}.${timeMessage}`;
    await addNotification(requestId, message);
    await addRequestAudit(req, "request_status_updated_by_worker", "request", requestId, {
      status: nextStatus,
      timeSpentMinutes,
    });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to update request status." });
  }
});

app.get("/api/admin/audit-logs", requireAdmin, async (req, res) => {
  const requestedLimit = Number.parseInt(String(req.query.limit || "100"), 10);
  const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 500) : 100;

  try {
    const logs = await allSql(
      `
        SELECT id, actor_role as actorRole, actor_identifier as actorIdentifier, action, target_type as targetType,
               target_id as targetId, metadata, created_at as createdAt
        FROM audit_logs
        ORDER BY datetime(created_at) DESC
        LIMIT ?
      `,
      [limit]
    );
    res.json(logs);
  } catch {
    res.status(500).json({ error: "Failed to load audit logs." });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Assistance tracker running on http://localhost:${PORT}`);
});
