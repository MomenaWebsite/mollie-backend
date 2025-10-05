/**
 * Cart + Mollie Payments backend — met persistente Accounts (JWT + Prisma/Postgres)
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
const { PrismaClient } = require("@prisma/client");
const fetch =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

/* ------------ ENV ------------ */
const MOLLIE_API_KEY  = process.env.MOLLIE_API_KEY;
const FRONTEND_URL    = (process.env.FRONTEND_URL    || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
// Belangrijk: verander JWT_SECRET niet per deploy, anders logt iedereen uit
const JWT_SECRET      = process.env.JWT_SECRET || "change-me-in-env";

if (!MOLLIE_API_KEY)  console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL)    console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL) console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");
if (JWT_SECRET === "change-me-in-env") console.warn("⚠️ Set a strong JWT_SECRET in env");

/* ------------ CORS & body parsing ------------ */
/** credentials:true zodat cookies (JWT) werken in de browser (cross-site). */
function parseOrigins(input) {
  const s = String(input || "").trim();
  if (!s) return [];
  return s.split(",").map(x => x.trim()).filter(Boolean);
}
const ALLOWED_ORIGINS = parseOrigins(FRONTEND_URL); // ondersteunt ook komma-gescheiden lijst

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/postman
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked for origin: " + origin));
  },
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use("/api/mollie/webhook", express.urlencoded({ extended: false }));

/* ------------ In-memory order status (ok, dit mag in memory) ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();

/* ------------ Users (DB via Prisma) ------------ */
// Verwacht Prisma model:
//
// model User {
//   id         String   @id @default(cuid())
//   email      String   @unique
//   password   String
//   firstName  String?
//   lastName   String?
//   street     String?
//   number     String?
//   postalCode String?
//   city       String?
//   country    String?
//   phone      String?
//   createdAt  DateTime @default(now())
//   updatedAt  DateTime @updatedAt
// }

async function findUserByEmail(email) {
  const e = String(email || "").toLowerCase();
  if (!e) return null;
  return prisma.user.findUnique({ where: { email: e } });
}
async function createUser({ email, password, profile }) {
  const hash = await bcrypt.hash(String(password), 10);
  const data = {
    email: String(email).toLowerCase(),
    password: hash,
    firstName: profile?.firstName || null,
    lastName: profile?.lastName || null,
    street: profile?.street || null,
    number: profile?.number || null,
    postalCode: profile?.postalCode || null,
    city: profile?.city || null,
    country: profile?.country || null,
    phone: profile?.phone || null,
  };
  return prisma.user.create({ data });
}
async function updateUserProfile(userId, profile = {}) {
  return prisma.user.update({
    where: { id: userId },
    data: {
      firstName: profile.firstName ?? undefined,
      lastName: profile.lastName ?? undefined,
      street: profile.street ?? undefined,
      number: profile.number ?? undefined,
      postalCode: profile.postalCode ?? undefined,
      city: profile.city ?? undefined,
      country: profile.country ?? undefined,
      phone: profile.phone ?? undefined,
    },
  });
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

    const exists = await findUserByEmail(email);
    if (exists) return res.status(400).json({ error: "Account bestaat al" });

    const user = await createUser({ email, password, profile });

    const token = signJwt({ userId: user.id, email: user.email });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,         // Render is https -> true
      sameSite: "none",     // cross-site cookie (Framer <> backend)
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    res.json({
      ok: true,
      user: {
        email: user.email,
        profile: {
          firstName: user.firstName || "",
          lastName: user.lastName || "",
          street: user.street || "",
          number: user.number || "",
          postalCode: user.postalCode || "",
          city: user.city || "",
          country: user.country || "",
          phone: user.phone || "",
          email: user.email,
        },
      },
    });
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ error: "Signup mislukt" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await findUserByEmail(email);
    if (!user) return res.status(400).json({ error: "Onbekend account" });

    const ok = await bcrypt.compare(String(password || ""), user.password);
    if (!ok) return res.status(400).json({ error: "Ongeldig wachtwoord" });

    const token = signJwt({ userId: user.id, email: user.email });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    res.json({
      ok: true,
      user: {
        email: user.email,
        profile: {
          firstName: user.firstName || "",
          lastName: user.lastName || "",
          street: user.street || "",
          number: user.number || "",
          postalCode: user.postalCode || "",
          city: user.city || "",
          country: user.country || "",
          phone: user.phone || "",
          email: user.email,
        },
      },
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Login mislukt" });
  }
});

app.post("/api/logout", (_req, res) => {
  res.clearCookie("token", { path: "/", sameSite: "none", secure: true });
  res.json({ ok: true });
});

app.get("/api/me", authRequired, async (req, res) => {
  try {
    const me = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!me) return res.status(404).json({ error: "Niet gevonden" });
    res.json({
      email: me.email,
      profile: {
        firstName: me.firstName || "",
        lastName: me.lastName || "",
        street: me.street || "",
        number: me.number || "",
        postalCode: me.postalCode || "",
        city: me.city || "",
        country: me.country || "",
        phone: me.phone || "",
        email: me.email,
      },
    });
  } catch (e) {
    console.error("Me error:", e);
    res.status(500).json({ error: "Niet gevonden" });
  }
});

app.put("/api/me", authRequired, async (req, res) => {
  try {
    const p = req.body?.profile || {};
    const updated = await updateUserProfile(req.user.userId, p);
    res.json({
      ok: true,
      profile: {
        firstName: updated.firstName || "",
        lastName: updated.lastName || "",
        street: updated.street || "",
        number: updated.number || "",
        postalCode: updated.postalCode || "",
        city: updated.city || "",
        country: updated.country || "",
        phone: updated.phone || "",
        email: updated.email,
      },
    });
  } catch (e) {
    console.error("Update profile error:", e);
    res.status(500).json({ error: "Opslaan mislukt" });
  }
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
