/**
 * Cart + Mollie Payments backend (robuste /api/products) — met eenvoudige Accounts (JWT + file store)
 */
try { require("dotenv").config(); } catch {}

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fetch =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const app = express();
const PORT = process.env.PORT || 3000;

/* ------------ ENV ------------ */
const MOLLIE_API_KEY  = process.env.MOLLIE_API_KEY;
const FRONTEND_URL    = (process.env.FRONTEND_URL    || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const JWT_SECRET      = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex"); // zet zelf in .env!

if (!MOLLIE_API_KEY)  console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL)    console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL) console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");

/* ------------ CORS & body parsing ------------ */
/** LET OP: credentials:true zodat cookies (JWT) werken in de browser (cross-site). */
app.use(cors({
  origin: FRONTEND_URL || "*",
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use("/api/mollie/webhook", express.urlencoded({ extended: false }));

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();

/* ------------ Users (file store) ------------ */
const USERS_PATH = path.join(__dirname, "users.json");
function readUsersFile() {
  try {
    const raw = fs.readFileSync(USERS_PATH, "utf8");
    const json = JSON.parse(raw);
    return Array.isArray(json?.users) ? json.users : [];
  } catch {
    return [];
  }
}
function writeUsersFile(users) {
  fs.writeFileSync(USERS_PATH, JSON.stringify({ users }, null, 2));
}
function findUserByEmail(email) {
  const users = readUsersFile();
  return users.find(u => u.email.toLowerCase() === String(email || "").toLowerCase());
}
function saveUser(user) {
  const users = readUsersFile();
  const i = users.findIndex(u => u.email.toLowerCase() === user.email.toLowerCase());
  if (i >= 0) users[i] = user; else users.push(user);
  writeUsersFile(users);
}

/* ------------ Auth helpers ------------ */
function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}
function authRequired(req, res, next) {
  try {
    const token = req.cookies?.token || "";
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data; // { userId, email }
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

/* ------------ Products helpers ------------ */
const PRODUCTS_PATH = path.join(__dirname, "products.json");

function loadCatalog() {
  try {
    const raw = fs.readFileSync(PRODUCTS_PATH, "utf8");
    const json = JSON.parse(raw);
    const list = Array.isArray(json) ? json : json?.products || [];
    return list.map((p) => {
      const priceRaw = typeof p.price === "string" ? p.price.replace(",", ".") : p.price;
      const price = Number(priceRaw) || 0;
      return {
        id: String(p.id),
        name: String(p.name),
        price,
        image: p.image || undefined,
      };
    });
  } catch (e) {
    console.error("Failed to load/parse products.json:", e.message);
    return [];
  }
}

function calcTotal(items) {
  let sum = 0;
  const catalog = loadCatalog();
  for (const it of items || []) {
    const p = catalog.find((x) => x.id === it.id);
    const qty = Math.max(0, Number(it.qty || 0));
    if (!p || qty <= 0) continue;
    sum += (p.price || 0) * qty;
  }
  return Number(sum.toFixed(2));
}

/* ------------ Mollie helper ------------ */
async function mollie(pathname, method = "GET", body) {
  const res = await fetch(`https://api.mollie.com/v2${pathname}`, {
    method,
    headers: {
      Authorization: `Bearer ${MOLLIE_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`Mollie ${res.status}: ${await res.text()}`);
  return res.json();
}

/* =========================
   ROUTES
========================= */
app.get("/", (_req, res) => res.send("Cart backend up ✅"));

/** Products */
app.get("/api/products", (_req, res) => {
  const catalog = loadCatalog();
  res.set("Cache-Control", "no-store");
  res.json({ products: catalog });
});

/* --------- AUTH: signup/login/me/logout + profiel opslaan ---------- */
/**
 * Profiel shape (sender):
 * {
 *   firstName, lastName, street, number, postalCode, city, country, phone, email
 * }
 */
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, profile } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email en password verplicht" });

    if (findUserByEmail(email)) return res.status(400).json({ error: "Account bestaat al" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = {
      id: crypto.randomUUID(),
      email: String(email),
      passwordHash,
      profile: {
        firstName: profile?.firstName || "",
        lastName: profile?.lastName || "",
        street: profile?.street || "",
        number: profile?.number || "",
        postalCode: profile?.postalCode || "",
        city: profile?.city || "",
        country: profile?.country || "",
        phone: profile?.phone || "",
        email: String(email), // mag gelijk zijn aan login email
      },
      createdAt: new Date().toISOString(),
    };
    saveUser(user);

    const token = signJwt({ userId: user.id, email: user.email });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,         // Render is https -> true
      sameSite: "none",     // cross-site cookie (Framer <> backend)
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    res.json({ ok: true, user: { email: user.email, profile: user.profile } });
  } catch (e) {
    res.status(500).json({ error: "Signup mislukt" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = findUserByEmail(email);
    if (!user) return res.status(400).json({ error: "Onbekend account" });
    const ok = await bcrypt.compare(String(password || ""), user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Ongeldig wachtwoord" });

    const token = signJwt({ userId: user.id, email: user.email });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    res.json({ ok: true, user: { email: user.email, profile: user.profile } });
  } catch {
    res.status(500).json({ error: "Login mislukt" });
  }
});

app.post("/api/logout", (_req, res) => {
  res.clearCookie("token", { httpOnly: true, secure: true, sameSite: "none" });
  res.json({ ok: true });
});

app.get("/api/me", authRequired, (req, res) => {
  const me = findUserByEmail(req.user.email);
  if (!me) return res.status(404).json({ error: "Niet gevonden" });
  res.json({ email: me.email, profile: me.profile });
});

app.put("/api/me", authRequired, (req, res) => {
  const me = findUserByEmail(req.user.email);
  if (!me) return res.status(404).json({ error: "Niet gevonden" });

  const p = req.body?.profile || {};
  me.profile = {
    firstName: p.firstName || "",
    lastName: p.lastName || "",
    street: p.street || "",
    number: p.number || "",
    postalCode: p.postalCode || "",
    city: p.city || "",
    country: p.country || "",
    phone: p.phone || "",
    email: me.email,
  };
  saveUser(me);
  res.json({ ok: true, profile: me.profile });
});

/* --------- Checkout (metadata bevat sender + senderPrefs indien meegestuurd) ---------- */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const sender = req.body?.sender || null;          // optioneel (komt uit account of formulier)
    const senderPrefs = req.body?.senderPrefs || {};  // optioneel
    const orderId = req.body?.orderId || `order_${Date.now()}`;

    const total = calcTotal(items);
    if (!total || total <= 0) {
      return res.status(400).json({ error: "Cart is empty or invalid" });
    }

    const description = `Order ${orderId} – ${items.length} items`;

    const payment = await mollie("/payments", "POST", {
      amount: { currency: "EUR", value: total.toFixed(2) },
      description,
      redirectUrl: `${FRONTEND_URL}/bedankt?orderId=${encodeURIComponent(orderId)}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      metadata: { orderId, items, sender, senderPrefs },
    });

    if (payment?.metadata?.orderId && payment?.id) {
      paymentIdByOrderId.set(payment.metadata.orderId, payment.id);
    }

    const checkoutUrl = payment?._links?.checkout?.href;
    if (!checkoutUrl) throw new Error("No checkout URL from Mollie");

    res.json({ checkoutUrl, paymentId: payment.id, orderId, total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create payment" });
  }
});

/* --------- Webhook & status ---------- */
app.post("/api/mollie/webhook", async (req, res) => {
  const paymentId = req.body?.id;
  if (!paymentId) return res.status(200).send("OK");

  try {
    const payment = await mollie(`/payments/${paymentId}`, "GET");
    const status = payment?.status || "unknown";
    const orderId = payment?.metadata?.orderId;

    if (orderId) {
      statusesByOrderId.set(orderId, status);
      paymentIdByOrderId.set(orderId, paymentId);
      console.log(`🔔 ${orderId} -> ${status}`);
    }
    res.status(200).send("OK");
  } catch (e) {
    console.error("Webhook error:", e);
    res.status(500).send("Webhook error");
  }
});

app.get("/api/order-status", (req, res) => {
  const orderId = req.query.orderId;
  if (!orderId) return res.status(400).json({ error: "orderId required" });
  const status = statusesByOrderId.get(orderId) || "unknown";
  const paymentId = paymentIdByOrderId.get(orderId) || null;
  res.json({ orderId, status, paymentId });
});

app.get("/api/payment-status", async (req, res) => {
  const paymentId = req.query.paymentId;
  if (!paymentId) return res.status(400).json({ error: "paymentId required" });
  try {
    const payment = await mollie(`/payments/${paymentId}`, "GET");
    res.json({ paymentId, status: payment?.status || "unknown" });
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch status" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server on :${PORT}`);
  console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
  console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
});
