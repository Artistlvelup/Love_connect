const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const ffprobe = require("ffprobe-static");
const { execFile } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const execFileAsync = promisify(execFile);

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required. Configure PostgreSQL before starting the server.");
  process.exit(1);
}
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.error("In production, set SESSION_SECRET to a random value of at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined
});

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.set("trust proxy", 1);
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  name: "loveconnect.sid",
  secret: process.env.SESSION_SECRET || "local-development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: isProduction, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });
const allowedVideoTypes = new Set(["video/mp4", "video/webm", "video/quicktime"]);
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase().slice(0, 8))
  }),
  limits: { fileSize: 40 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => cb(null, allowedVideoTypes.has(file.mimetype))
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL, birth_date DATE NOT NULL, country TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '', looking_for TEXT NOT NULL DEFAULT 'Connections',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS likes (
      from_member BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      to_member BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (from_member, to_member), CHECK (from_member <> to_member)
    );
    CREATE TABLE IF NOT EXISTS matches (
      member_a BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      member_b BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (member_a, member_b), CHECK (member_a < member_b)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY, sender_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      recipient_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      body TEXT NOT NULL CHECK (char_length(body) <= 2000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages(sender_id, recipient_id, created_at);
    CREATE TABLE IF NOT EXISTS videos (
      id BIGSERIAL PRIMARY KEY, member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      filename TEXT NOT NULL, original_name TEXT NOT NULL, duration_seconds NUMERIC(6,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS member_blocks (
      blocker_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      blocked_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (blocker_id, blocked_id), CHECK (blocker_id <> blocked_id)
    );
    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY, reporter_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      reported_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

function requireAuth(req, res, next) {
  if (!req.session.memberId) return res.status(401).json({ error: "Please log in first." });
  next();
}
function publicMember(row) {
  return { id: row.id, displayName: row.display_name, country: row.country, bio: row.bio, lookingFor: row.looking_for };
}
function validAdultDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || "")) return false;
  const date = new Date(value + "T00:00:00Z");
  if (Number.isNaN(date.getTime())) return false;
  const now = new Date();
  let age = now.getUTCFullYear() - date.getUTCFullYear();
  if (now.getUTCMonth() < date.getUTCMonth() || (now.getUTCMonth() === date.getUTCMonth() && now.getUTCDate() < date.getUTCDate())) age--;
  return age >= 18 && date <= now;
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "Love Connect API" }));

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { email, password, displayName, birthDate, country } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 10 ||
        !displayName || displayName.trim().length > 60 || !validAdultDate(birthDate)) {
      return res.status(400).json({ error: "Enter a valid email, a password of at least 10 characters, a name, and a birth date confirming you are 18 or older." });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO members(email,password_hash,display_name,birth_date,country) VALUES($1,$2,$3,$4,$5) RETURNING id,email,display_name,country,bio,looking_for",
      [email.toLowerCase().trim(), hash, displayName.trim(), birthDate, String(country || "").slice(0, 80)]
    );
    req.session.memberId = result.rows[0].id;
    res.status(201).json({ member: publicMember(result.rows[0]) });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "That email already has an account." });
    next(err);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").toLowerCase().trim();
    const result = await pool.query("SELECT * FROM members WHERE email=$1", [email]);
    if (!result.rowCount || !(await bcrypt.compare(String(req.body?.password || ""), result.rows[0].password_hash))) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.memberId = result.rows[0].id;
      res.json({ member: publicMember(result.rows[0]) });
    });
  } catch (err) { next(err); }
});

app.post("/api/auth/logout", (req, res, next) => req.session.destroy(err => err ? next(err) : res.clearCookie("loveconnect.sid").json({ ok: true })));
app.get("/api/me", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query("SELECT id,email,display_name,country,bio,looking_for FROM members WHERE id=$1", [req.session.memberId]);
    if (!r.rowCount) return res.status(401).json({ error: "Account not found." });
    res.json({ member: { ...publicMember(r.rows[0]), email: r.rows[0].email } });
  } catch (err) { next(err); }
});

app.patch("/api/me", requireAuth, async (req, res, next) => {
  try {
    const { displayName, country, bio, lookingFor } = req.body || {};
    if (!displayName || String(displayName).trim().length > 60 || String(bio || "").length > 500 ||
        String(country || "").length > 80 || String(lookingFor || "Connections").length > 80) {
      return res.status(400).json({ error: "Please check your profile fields." });
    }
    const r = await pool.query(
      "UPDATE members SET display_name=$1,country=$2,bio=$3,looking_for=$4 WHERE id=$5 RETURNING id,email,display_name,country,bio,looking_for",
      [String(displayName).trim(), String(country || ""), String(bio || ""), String(lookingFor || "Connections"), req.session.memberId]
    );
    res.json({ member: { ...publicMember(r.rows[0]), email: r.rows[0].email } });
  } catch (err) { next(err); }
});

app.get("/api/discover", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT m.id,m.display_name,m.country,m.bio,m.looking_for
      FROM members m
      WHERE m.id <> $1
        AND NOT EXISTS (SELECT 1 FROM member_blocks b WHERE (b.blocker_id=$1 AND b.blocked_id=m.id) OR (b.blocker_id=m.id AND b.blocked_id=$1))
        AND NOT EXISTS (SELECT 1 FROM likes l WHERE l.from_member=$1 AND l.to_member=m.id)
      ORDER BY m.created_at DESC LIMIT 50
    `, [req.session.memberId]);
    const ids = r.rows.map(x => x.id);
    let videoRows = [];
    if (ids.length) {
      const v = await pool.query("SELECT DISTINCT ON(member_id) member_id,id,duration_seconds FROM videos WHERE member_id = ANY($1::bigint[]) ORDER BY member_id,created_at DESC", [ids]);
      videoRows = v.rows;
    }
    res.json({ members: r.rows.map(m => ({ ...publicMember(m), hasVideo: videoRows.some(v => String(v.member_id) === String(m.id)), videoId: (videoRows.find(v => String(v.member_id) === String(m.id)) || {}).id || null })) });
  } catch (err) { next(err); }
});

app.post("/api/likes/:memberId", requireAuth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const me = String(req.session.memberId), target = String(req.params.memberId);
    if (me === target) return res.status(400).json({ error: "You cannot like your own profile." });
    await client.query("BEGIN");
    const targetExists = await client.query("SELECT id FROM members WHERE id=$1", [target]);
    if (!targetExists.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Member not found." }); }
    const blocked = await client.query("SELECT 1 FROM member_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)", [me,target]);
    if (blocked.rowCount) { await client.query("ROLLBACK"); return res.status(403).json({ error: "This interaction is unavailable." }); }
    await client.query("INSERT INTO likes(from_member,to_member) VALUES($1,$2) ON CONFLICT DO NOTHING", [me,target]);
    const reciprocal = await client.query("SELECT 1 FROM likes WHERE from_member=$1 AND to_member=$2", [target,me]);
    let matched = false;
    if (reciprocal.rowCount) {
      const a = BigInt(me) < BigInt(target) ? me : target;
      const b = a === me ? target : me;
      await client.query("INSERT INTO matches(member_a,member_b) VALUES($1,$2) ON CONFLICT DO NOTHING", [a,b]);
      matched = true;
    }
    await client.query("COMMIT");
    res.json({ liked: true, matched });
  } catch (err) { await client.query("ROLLBACK").catch(()=>{}); next(err); }
  finally { client.release(); }
});

app.get("/api/matches", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT m.id,m.display_name,m.country,m.bio,m.looking_for
      FROM matches x JOIN members m ON m.id = CASE WHEN x.member_a=$1 THEN x.member_b ELSE x.member_a END
      WHERE x.member_a=$1 OR x.member_b=$1
      ORDER BY x.created_at DESC
    `, [req.session.memberId]);
    res.json({ matches: r.rows.map(publicMember) });
  } catch (err) { next(err); }
});

app.get("/api/messages/:memberId", requireAuth, async (req, res, next) => {
  try {
    const me = String(req.session.memberId), other = String(req.params.memberId);
    const match = await pool.query("SELECT 1 FROM matches WHERE (member_a=$1 AND member_b=$2) OR (member_a=$2 AND member_b=$1)", [me,other]);
    if (!match.rowCount) return res.status(403).json({ error: "Private messaging is available only between matches." });
    const r = await pool.query(`
      SELECT id,sender_id,recipient_id,body,created_at FROM messages
      WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)
      ORDER BY created_at ASC LIMIT 300
    `, [me,other]);
    res.json({ messages: r.rows });
  } catch (err) { next(err); }
});

app.post("/api/messages/:memberId", requireAuth, async (req, res, next) => {
  try {
    const me = String(req.session.memberId), other = String(req.params.memberId);
    const body = String(req.body?.body || "").trim();
    if (!body || body.length > 2000) return res.status(400).json({ error: "Message must be 1–2000 characters." });
    const match = await pool.query("SELECT 1 FROM matches WHERE (member_a=$1 AND member_b=$2) OR (member_a=$2 AND member_b=$1)", [me,other]);
    if (!match.rowCount) return res.status(403).json({ error: "Private messaging is available only between matches." });
    const blocked = await pool.query("SELECT 1 FROM member_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)", [me,other]);
    if (blocked.rowCount) return res.status(403).json({ error: "Messaging is unavailable." });
    const r = await pool.query("INSERT INTO messages(sender_id,recipient_id,body) VALUES($1,$2,$3) RETURNING id,sender_id,recipient_id,body,created_at", [me,other,body]);
    res.status(201).json({ message: r.rows[0] });
  } catch (err) { next(err); }
});

app.post("/api/videos", requireAuth, (req, res, next) => {
  upload.single("video")(req, res, async err => {
    if (err) return res.status(400).json({ error: "Upload rejected. Use MP4, WebM, or MOV video under 40 MB." });
    if (!req.file) return res.status(400).json({ error: "Choose an MP4, WebM, or MOV video." });
    try {
      const { stdout } = await execFileAsync(ffprobe.path, ["-v","error","-show_entries","format=duration","-of","default=noprint_wrappers=1:nokey=1",req.file.path]);
      const duration = Number(stdout.trim());
      if (!Number.isFinite(duration) || duration <= 0 || duration > 30) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: "Videos must be 30 seconds or shorter." });
      }
      const r = await pool.query("INSERT INTO videos(member_id,filename,original_name,duration_seconds) VALUES($1,$2,$3,$4) RETURNING id,duration_seconds,created_at", [req.session.memberId,req.file.filename,req.file.originalname.slice(0,255),duration]);
      res.status(201).json({ video: r.rows[0], note: "Uploaded. Production launch requires durable video storage and moderation." });
    } catch (e) {
      fs.unlink(req.file.path, () => {});
      next(e);
    }
  });
});

app.get("/api/videos/:id", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query("SELECT v.filename,v.original_name,v.duration_seconds FROM videos v WHERE v.id=$1 AND NOT EXISTS (SELECT 1 FROM member_blocks b WHERE (b.blocker_id=$2 AND b.blocked_id=v.member_id) OR (b.blocker_id=v.member_id AND b.blocked_id=$2))", [req.params.id,req.session.memberId]);
    if (!r.rowCount) return res.status(404).json({ error: "Video not found." });
    res.sendFile(path.join(uploadDir, path.basename(r.rows[0].filename)));
  } catch (err) { next(err); }
});

app.post("/api/members/:memberId/block", requireAuth, async (req, res, next) => {
  try {
    const other = String(req.params.memberId), me = String(req.session.memberId);
    if (other === me) return res.status(400).json({ error: "You cannot block yourself." });
    await pool.query("INSERT INTO member_blocks(blocker_id,blocked_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [me,other]);
    await pool.query("DELETE FROM matches WHERE (member_a=$1 AND member_b=$2) OR (member_a=$2 AND member_b=$1)", [me,other]);
    res.json({ blocked: true });
  } catch (err) { next(err); }
});

app.post("/api/members/:memberId/report", requireAuth, async (req, res, next) => {
  try {
    const other = String(req.params.memberId), me = String(req.session.memberId);
    const reason = String(req.body?.reason || "").slice(0,100);
    const details = String(req.body?.details || "").slice(0,1000);
    if (other === me || !reason) return res.status(400).json({ error: "Choose a report reason." });
    await pool.query("INSERT INTO reports(reporter_id,reported_id,reason,details) VALUES($1,$2,$3,$4)", [me,other,reason,details]);
    res.status(201).json({ reported: true });
  } catch (err) { next(err); }
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

initDb().then(() => {
  app.listen(port, () => console.log(`Love Connect API listening on ${port}`));
}).catch(err => {
  console.error("Database initialization failed:", err.message);
  process.exit(1);
});
