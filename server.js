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

const databaseUrl = new URL(process.env.DATABASE_URL);
// When DATABASE_SSL=true, remove URL SSL parameters so node-postgres does not
// override the explicit TLS configuration below.
if (process.env.DATABASE_SSL === "true") {
  databaseUrl.searchParams.delete("sslmode");
  databaseUrl.searchParams.delete("ssl");
}
const pool = new Pool({
  connectionString: databaseUrl.toString(),
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined
});

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb", verify: (req, _res, buf) => { req.rawBody = Buffer.from(buf); } }));
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
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
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
    CREATE TABLE IF NOT EXISTS subscriptions (
      id BIGSERIAL PRIMARY KEY, member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      plan_code TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'inactive' CHECK (status IN ('inactive','active','cancelled','expired')),
      provider TEXT NOT NULL DEFAULT 'paystack', provider_reference TEXT UNIQUE,
      starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS subscriptions_member_status_idx ON subscriptions(member_id,status,ends_at);
    CREATE TABLE IF NOT EXISTS call_signals (
      id BIGSERIAL PRIMARY KEY, call_id UUID NOT NULL,
      from_member BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      to_member BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      signal_type TEXT NOT NULL CHECK (signal_type IN ('offer','answer','ice','end')),
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS call_signals_recipient_idx ON call_signals(to_member,id);
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
    CREATE TABLE IF NOT EXISTS sponsor_campaigns (
      id BIGSERIAL PRIMARY KEY, member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      business_name TEXT NOT NULL, campaign_title TEXT NOT NULL, description TEXT NOT NULL,
      website_url TEXT NOT NULL DEFAULT '', package_code TEXT NOT NULL,
      amount_kobo INTEGER NOT NULL, duration_days INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'awaiting_payment' CHECK (status IN ('awaiting_payment','pending_review','approved','rejected','completed')),
      payment_reference TEXT UNIQUE, paid_at TIMESTAMPTZ, starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS sponsor_campaigns_member_idx ON sponsor_campaigns(member_id,created_at DESC);
  `);
  await pool.query("ALTER TABLE members ADD COLUMN IF NOT EXISTS photo_data BYTEA, ADD COLUMN IF NOT EXISTS photo_type TEXT");
}

function requireAuth(req, res, next) {
  if (!req.session.memberId) return res.status(401).json({ error: "Please log in first." });
  next();
}
async function requireActiveSubscription(req, res, next) {
  try {
    const r = await pool.query(
      "SELECT 1 FROM subscriptions WHERE member_id=$1 AND status='active' AND (ends_at IS NULL OR ends_at > now()) ORDER BY created_at DESC LIMIT 1",
      [req.session.memberId]
    );
    if (!r.rowCount) return res.status(402).json({
      error: "This is a paid Love Connect feature. Choose a subscription plan to unlock it."
    });
    next();
  } catch (err) { next(err); }
}
function publicMember(row) {
  return { id: row.id, displayName: row.display_name, country: row.country, bio: row.bio, lookingFor: row.looking_for, photoUrl: "/api/members/" + row.id + "/photo" };
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

const paidPlans = {
  monthly: { amount: 200000, days: 30, label: "Monthly" },
  quarterly: { amount: 500000, days: 90, label: "3 months" },
  yearly: { amount: 1500000, days: 365, label: "Yearly" }
};
function paystackConfigured() { return !!process.env.PAYSTACK_SECRET_KEY; }
async function paystackRequest(endpoint, body) {
  const response = await fetch("https://api.paystack.co" + endpoint, {
    method: body ? "POST" : "GET",
    headers: { Authorization: "Bearer " + process.env.PAYSTACK_SECRET_KEY, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.status) throw new Error(data.message || "Paystack request failed.");
  return data.data;
}
async function verifyAndActivatePaystack(reference, expectedMemberId) {
  if (!paystackConfigured()) throw new Error("Paystack has not been configured by the site administrator.");
  const tx = await paystackRequest("/transaction/verify/" + encodeURIComponent(reference));
  const meta = tx.metadata || {};
  const plan = paidPlans[String(meta.plan_code || "")];
  if (tx.status !== "success" || tx.currency !== "NGN" || !plan ||
      Number(tx.amount) !== plan.amount || String(meta.member_id) !== String(expectedMemberId || meta.member_id) ||
      String(tx.reference) !== String(reference)) {
    throw new Error("Payment could not be verified against the selected Love Connect plan.");
  }
  const memberId = String(meta.member_id || "");
  if (!/^\d+$/.test(memberId)) throw new Error("Payment is missing a valid member reference.");
  const existing = await pool.query("SELECT id FROM subscriptions WHERE provider_reference=$1", [reference]);
  if (existing.rowCount) return;
  const startsAt = new Date();
  const endsAt = new Date(startsAt.getTime() + plan.days * 24 * 60 * 60 * 1000);
  await pool.query(
    "INSERT INTO subscriptions(member_id,plan_code,status,provider,provider_reference,starts_at,ends_at) VALUES($1,$2,'active','paystack',$3,$4,$5) ON CONFLICT(provider_reference) DO NOTHING",
    [memberId, meta.plan_code, reference, startsAt.toISOString(), endsAt.toISOString()]
  );
}
const sponsorPlans = {
  weekly: { amount: 1000000, days: 7, label: "7 days", price: "₦10,000" },
  monthly: { amount: 2500000, days: 30, label: "30 days", price: "₦25,000" },
  quarterly: { amount: 6000000, days: 90, label: "90 days", price: "₦60,000" }
};
app.get("/api/advertising/packages", (_req, res) => res.json({ currency: "NGN", packages: Object.entries(sponsorPlans).map(([code,p]) => ({ code, label: p.label, price: p.price, amount: p.amount / 100, days: p.days })) }));
app.post("/api/advertising/campaigns", requireAuth, async (req, res, next) => {
  try {
    const businessName = String(req.body?.businessName || "").trim().slice(0,100);
    const title = String(req.body?.title || "").trim().slice(0,100);
    const description = String(req.body?.description || "").trim().slice(0,500);
    let website = String(req.body?.website || "").trim().slice(0,300);
    const packageCode = String(req.body?.packageCode || "");
    const plan = sponsorPlans[packageCode];
    if (!businessName || !title || !description || !plan) return res.status(400).json({ error: "Enter your business name, advert title, description, and package." });
    if (website) {
      try { const u = new URL(website); if (!["http:","https:"].includes(u.protocol)) throw new Error(); website = u.toString(); }
      catch { return res.status(400).json({ error: "Enter a valid website link beginning with https:// or http://." }); }
    }
    if (!paystackConfigured()) return res.status(503).json({ error: "Advert booking is ready, but Paystack checkout is not connected yet. The site administrator must add the live Paystack key." });
    const member = await pool.query("SELECT email FROM members WHERE id=$1", [req.session.memberId]);
    if (!member.rowCount) return res.status(401).json({ error: "Please log in again." });
    const baseUrl = String(process.env.APP_URL || "").replace(/\/$/, "");
    if (!baseUrl || !/^https:\/\//i.test(baseUrl)) return res.status(503).json({ error: "The site administrator must set APP_URL to the public HTTPS Love Connect website address." });
    const inserted = await pool.query(
      "INSERT INTO sponsor_campaigns(member_id,business_name,campaign_title,description,website_url,package_code,amount_kobo,duration_days) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
      [req.session.memberId,businessName,title,description,website,packageCode,plan.amount,plan.days]
    );
    try {
      const tx = await paystackRequest("/transaction/initialize", {
        email: member.rows[0].email, amount: plan.amount, currency: "NGN",
        callback_url: baseUrl + "/api/payments/paystack/callback",
        metadata: { product: "Love Connect sponsored campaign", campaign_id: String(inserted.rows[0].id), member_id: String(req.session.memberId), package_code: packageCode }
      });
      await pool.query("UPDATE sponsor_campaigns SET payment_reference=$1,updated_at=now() WHERE id=$2", [tx.reference,inserted.rows[0].id]);
      res.json({ authorizationUrl: tx.authorization_url, reference: tx.reference, campaignId: inserted.rows[0].id });
    } catch (e) {
      await pool.query("UPDATE sponsor_campaigns SET status='rejected',updated_at=now() WHERE id=$1", [inserted.rows[0].id]);
      throw e;
    }
  } catch (err) { next(err); }
});
app.get("/api/advertising/my-campaigns", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query("SELECT id,business_name,campaign_title,package_code,amount_kobo,duration_days,status,paid_at,starts_at,ends_at,created_at FROM sponsor_campaigns WHERE member_id=$1 ORDER BY created_at DESC LIMIT 50", [req.session.memberId]);
    res.json({ campaigns: r.rows.map(c => ({ ...c, amount: Number(c.amount_kobo) / 100 })) });
  } catch (err) { next(err); }
});
app.get("/api/advertising/admin/campaigns", requireAuth, async (req, res, next) => {
  try {
    const adminEmail = String(process.env.ADMIN_EMAIL || "").toLowerCase().trim();
    if (!adminEmail) return res.status(503).json({ error: "Admin review is not configured. Set ADMIN_EMAIL in the server environment." });
    const me = await pool.query("SELECT email FROM members WHERE id=$1", [req.session.memberId]);
    if (!me.rowCount || me.rows[0].email.toLowerCase() !== adminEmail) return res.status(403).json({ error: "Admin access only." });
    const r = await pool.query("SELECT c.*,m.email AS advertiser_email FROM sponsor_campaigns c JOIN members m ON m.id=c.member_id ORDER BY c.created_at DESC LIMIT 100");
    res.json({ campaigns: r.rows });
  } catch (err) { next(err); }
});
app.patch("/api/advertising/admin/campaigns/:id", requireAuth, async (req, res, next) => {
  try {
    const adminEmail = String(process.env.ADMIN_EMAIL || "").toLowerCase().trim();
    const me = await pool.query("SELECT email FROM members WHERE id=$1", [req.session.memberId]);
    if (!adminEmail || !me.rowCount || me.rows[0].email.toLowerCase() !== adminEmail) return res.status(403).json({ error: "Admin access only." });
    const status = String(req.body?.status || "");
    if (!["approved","rejected"].includes(status)) return res.status(400).json({ error: "Choose approved or rejected." });
    const r = await pool.query("UPDATE sponsor_campaigns SET status=$1,starts_at=CASE WHEN $1='approved' THEN now() ELSE starts_at END,ends_at=CASE WHEN $1='approved' THEN now() + (duration_days || ' days')::interval ELSE ends_at END,updated_at=now() WHERE id=$2 AND status='pending_review' RETURNING id,status,starts_at,ends_at", [status,req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: "Paid campaign not found or already reviewed." });
    res.json({ campaign: r.rows[0] });
  } catch (err) { next(err); }
});
app.get("/api/payments/paystack/config", (_req, res) => res.json({ configured: paystackConfigured(), currency: "NGN", plans: Object.keys(paidPlans), advertisingConfigured: paystackConfigured() }));
app.post("/api/payments/paystack/initialize", requireAuth, async (req, res, next) => {
  try {
    if (!paystackConfigured()) return res.status(503).json({ error: "Paystack is not connected yet. The site administrator must add the Paystack secret key in the server's private environment settings." });
    const planCode = String(req.body?.planCode || "");
    const plan = paidPlans[planCode];
    if (!plan) return res.status(400).json({ error: "Choose a valid membership plan." });
    const member = await pool.query("SELECT email FROM members WHERE id=$1", [req.session.memberId]);
    if (!member.rowCount) return res.status(401).json({ error: "Please log in again." });
    const baseUrl = String(process.env.APP_URL || "").replace(/\/$/, "");
    if (!baseUrl || !/^https:\/\//i.test(baseUrl)) return res.status(503).json({ error: "The site administrator must set APP_URL to the public HTTPS Love Connect website address." });
    const tx = await paystackRequest("/transaction/initialize", {
      email: member.rows[0].email,
      amount: plan.amount,
      currency: "NGN",
      callback_url: baseUrl + "/api/payments/paystack/callback",
      metadata: { member_id: String(req.session.memberId), plan_code: planCode, product: "Love Connect membership" }
    });
    res.json({ authorizationUrl: tx.authorization_url, reference: tx.reference });
  } catch (err) { next(err); }
});
async function verifyAndActivateSponsor(reference, expectedMemberId) {
  if (!paystackConfigured()) throw new Error("Paystack has not been configured.");
  const tx = await paystackRequest("/transaction/verify/" + encodeURIComponent(reference));
  const meta = tx.metadata || {};
  const campaignId = String(meta.campaign_id || "");
  const memberId = String(meta.member_id || "");
  const campaign = await pool.query("SELECT * FROM sponsor_campaigns WHERE id=$1 AND member_id=$2 AND payment_reference=$3", [campaignId,memberId,reference]);
  if (tx.status !== "success" || tx.currency !== "NGN" || !campaign.rowCount ||
      String(expectedMemberId || memberId) !== memberId ||
      Number(tx.amount) !== Number(campaign.rows[0].amount_kobo) ||
      String(tx.reference) !== String(reference) || meta.product !== "Love Connect sponsored campaign") {
    throw new Error("Sponsored advert payment could not be verified.");
  }
  await pool.query("UPDATE sponsor_campaigns SET status=CASE WHEN status='awaiting_payment' THEN 'pending_review' ELSE status END,paid_at=COALESCE(paid_at,now()),updated_at=now() WHERE id=$1", [campaignId]);
}
app.get("/api/payments/paystack/callback", requireAuth, async (req, res) => {
  const baseUrl = String(process.env.APP_URL || "/").replace(/\/$/, "");
  try {
    const reference = String(req.query.reference || "");
    if (!reference) throw new Error("No payment reference was returned.");
    const tx = await paystackRequest("/transaction/verify/" + encodeURIComponent(reference));
    const product = tx.metadata?.product || "";
    if (product === "Love Connect sponsored campaign") await verifyAndActivateSponsor(reference, req.session.memberId);
    else await verifyAndActivatePaystack(reference, req.session.memberId);
    return res.redirect(baseUrl + "/?payment=" + (product === "Love Connect sponsored campaign" ? "ad_submitted" : "success"));
  } catch (err) {
    console.error("Paystack callback verification failed:", err.message);
    return res.redirect(baseUrl + "/?payment=not_verified");
  }
});
app.post("/api/payments/paystack/webhook", async (req, res) => {
  try {
    const signature = String(req.get("x-paystack-signature") || "");
    if (!paystackConfigured() || !signature || !req.rawBody) return res.sendStatus(401);
    const expected = crypto.createHmac("sha512", process.env.PAYSTACK_SECRET_KEY).update(req.rawBody).digest();
    let supplied;
    try { supplied = Buffer.from(signature, "hex"); } catch { return res.sendStatus(401); }
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return res.sendStatus(401);
    const event = req.body || {};
    if (event.event === "charge.success" && event.data?.reference) {
      const product = event.data.metadata?.product || "";
      if (product === "Love Connect sponsored campaign") await verifyAndActivateSponsor(String(event.data.reference), event.data.metadata?.member_id);
      else await verifyAndActivatePaystack(String(event.data.reference), event.data.metadata?.member_id);
    }
    return res.sendStatus(200);
  } catch (err) {
    console.error("Paystack webhook processing failed:", err.message);
    return res.sendStatus(500);
  }
});

app.get("/api/subscription", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      "SELECT plan_code,status,starts_at,ends_at FROM subscriptions WHERE member_id=$1 ORDER BY created_at DESC LIMIT 1",
      [req.session.memberId]
    );
    const subscription = r.rows[0] || null;
    const active = !!subscription && subscription.status === "active" && (!subscription.ends_at || new Date(subscription.ends_at) > new Date());
    res.json({ active, subscription, paidFeatures: ["video_uploads", "private_messaging", "video_calls"], paymentsConnected: paystackConfigured() });
  } catch (err) { next(err); }
});

app.post("/api/me/photo", requireAuth, (req, res, next) => {
  const photoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 512 * 1024, files: 1 }, fileFilter: (_req, file, cb) => {
    if (["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) return cb(null, true);
    cb(new Error("Choose a JPG, PNG, or WebP photo."));
  }}).single("photo");
  photoUpload(req, res, async err => {
    if (err) return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "Photo must be 512 KB or smaller." : (err.message || "Photo upload failed.") });
    if (!req.file) return res.status(400).json({ error: "Choose a JPG, PNG, or WebP photo." });
    try {
      await pool.query("UPDATE members SET photo_data=$1,photo_type=$2 WHERE id=$3", [req.file.buffer, req.file.mimetype, req.session.memberId]);
      res.json({ saved: true });
    } catch (e) { next(e); }
  });
});
app.get("/api/members/:memberId/photo", requireAuth, async (req, res, next) => {
  try {
    const blocked = await pool.query("SELECT 1 FROM member_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)", [req.session.memberId, req.params.memberId]);
    if (blocked.rowCount) return res.sendStatus(404);
    const r = await pool.query("SELECT photo_data,photo_type FROM members WHERE id=$1", [req.params.memberId]);
    if (!r.rowCount || !r.rows[0].photo_data) return res.sendStatus(404);
    res.set("Content-Type", r.rows[0].photo_type || "image/webp");
    res.set("Cache-Control", "private, max-age=300");
    res.send(r.rows[0].photo_data);
  } catch (err) { next(err); }
});

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { email, password, displayName, birthDate, country } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 10 ||
        !displayName || displayName.trim().length > 60 || !validAdultDate(birthDate)) {
      return res.status(400).json({ error: "Enter a valid email, a password of at least 10 characters, a name, and a birth date confirming you are 18 or older." });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO members(email,password_hash,display_name,birth_date,country,looking_for) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,email,display_name,country,bio,looking_for",
      [email.toLowerCase().trim(), hash, displayName.trim(), birthDate, String(country || "").slice(0, 80), String(req.body?.lookingFor || "Connections").slice(0, 80)]
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


async function validateCallPair(me, other) {
  if (String(me) === String(other)) return false;
  const [match, blocked] = await Promise.all([
    pool.query("SELECT 1 FROM matches WHERE (member_a=$1 AND member_b=$2) OR (member_a=$2 AND member_b=$1)", [me, other]),
    pool.query("SELECT 1 FROM member_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)", [me, other])
  ]);
  return !!match.rowCount && !blocked.rowCount;
}
app.get("/api/call-signals", requireAuth, requireActiveSubscription, async (req, res, next) => {
  try {
    const since = /^\d+$/.test(String(req.query.since || "0")) ? String(req.query.since || "0") : "0";
    const r = await pool.query(
      "SELECT id,call_id,from_member,to_member,signal_type,payload,created_at FROM call_signals WHERE to_member=$1 AND id>$2 AND created_at > now() - interval '10 minutes' ORDER BY id ASC LIMIT 100",
      [req.session.memberId, since]
    );
    res.json({ signals: r.rows });
  } catch (err) { next(err); }
});
app.post("/api/call-signals", requireAuth, requireActiveSubscription, async (req, res, next) => {
  try {
    const { callId, toMember, type, payload } = req.body || {};
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(callId || "")) ||
        !/^\d+$/.test(String(toMember || "")) || !["offer","answer","ice","end"].includes(type)) {
      return res.status(400).json({ error: "Invalid video call signal." });
    }
    const data = payload && typeof payload === "object" ? JSON.stringify(payload) : "{}";
    if (data.length > 20000) return res.status(413).json({ error: "Call signal is too large." });
    if (!(await validateCallPair(req.session.memberId, toMember))) return res.status(403).json({ error: "Video calls are only available between unblocked mutual matches." });
    const r = await pool.query(
      "INSERT INTO call_signals(call_id,from_member,to_member,signal_type,payload) VALUES($1,$2,$3,$4,$5::jsonb) RETURNING id",
      [callId, req.session.memberId, toMember, type, data]
    );
    res.status(201).json({ ok: true, id: r.rows[0].id });
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

app.post("/api/videos", requireAuth, requireActiveSubscription, (req, res, next) => {
  upload.single("video")(req, res, async err => {
    if (err) return res.status(400).json({ error: "Upload rejected. Use MP4, WebM, or MOV video up to 10 MB." });
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

app.get("/api/video-feed", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT v.id,v.member_id,v.duration_seconds,v.created_at,m.display_name,m.country,m.bio
      FROM videos v JOIN members m ON m.id=v.member_id
      WHERE NOT EXISTS (
        SELECT 1 FROM member_blocks b
        WHERE (b.blocker_id=$1 AND b.blocked_id=v.member_id)
           OR (b.blocker_id=v.member_id AND b.blocked_id=$1)
      )
      ORDER BY v.created_at DESC LIMIT 50
    `, [req.session.memberId]);
    res.json({ videos: r.rows.map(v => ({
      id: v.id, memberId: v.member_id, displayName: v.display_name,
      country: v.country, bio: v.bio, durationSeconds: Number(v.duration_seconds),
      createdAt: v.created_at, videoUrl: "/api/videos/" + v.id
    })) });
  } catch (err) { next(err); }
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
