/**
 * Cart + Mollie Payments backend — met persistente Accounts (JWT + Prisma/Postgres)
 */
try {
  require("dotenv").config();
} catch {}

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
const MOLLIE_API_KEY = process.env.MOLLIE_API_KEY;
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-env";
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "noreply@momena.nl";
const ORDER_EMAIL_TO = "bestellingen@momena.nl";

if (!MOLLIE_API_KEY) console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL) console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL)
  console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");
if (JWT_SECRET === "change-me-in-env")
  console.warn("⚠️ Set a strong JWT_SECRET in env");

/* ------------ CORS & body parsing ------------ */
function parseOrigins(input) {
  const s = String(input || "").trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}
const ALLOWED_ORIGINS = parseOrigins(FRONTEND_URL);

// Helper om de primaire frontend URL te krijgen (eerste URL uit de lijst)
function getPrimaryFrontendUrl() {
  const origins = parseOrigins(FRONTEND_URL);
  return origins.length > 0 ? origins[0] : FRONTEND_URL || "";
}

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked for origin: " + origin));
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/api/mollie/webhook", express.urlencoded({ extended: false }));

/* ------------ Helpers voor producten/voorraad ------------ */
const PRODUCTS_PATH = path.join(__dirname, "products.json");

function readCatalogState() {
  try {
    const raw = fs.readFileSync(PRODUCTS_PATH, "utf8");
    const data = JSON.parse(raw);
    if (Array.isArray(data)) {
      return { data, list: data, type: "array" };
    }
    if (data && Array.isArray(data.products)) {
      return { data, list: data.products, type: "object" };
    }
    return { data: [], list: [], type: "array" };
  } catch (e) {
    console.error("Failed to load/parse products.json:", e.message);
    return { data: [], list: [], type: "array" };
  }
}

function writeCatalogState(state) {
  const payload = state.type === "object" ? state.data : state.list;
  fs.writeFileSync(PRODUCTS_PATH, JSON.stringify(payload, null, 2));
}

function normalizeProduct(p) {
  if (!p) {
    return { id: "", name: "", price: 0, image: undefined, stock: 0 };
  }
  const priceRaw =
    typeof p.price === "string" ? p.price.replace(",", ".") : p.price;
  const price = Number(priceRaw) || 0;
  const stockRaw = Number(p.stock ?? 0);
  const stock = Number.isFinite(stockRaw)
    ? Math.max(0, Math.floor(stockRaw))
    : 0;

  return {
    id: String(p.id),
    name: String(p.name),
    price,
    image: p.image || undefined,
    stock,
  };
}

function loadCatalog() {
  const state = readCatalogState();
  return state.list.map(normalizeProduct);
}

function calcTotal(items, catalog = loadCatalog()) {
  let sum = 0;
  for (const it of items || []) {
    const product = catalog.find((x) => x.id === String(it.id));
    const qty = Math.max(0, Number(it.qty || 0));
    if (!product || qty <= 0) continue;
    sum += product.price * qty;
  }
  return Number(sum.toFixed(2));
}

function validateStock(items, catalog) {
  for (const it of items || []) {
    const product = catalog.find((x) => x.id === String(it.id));
    const qty = Math.max(0, Number(it.qty || 0));
    if (!product) {
      return `Product ${it.id} bestaat niet.`;
    }
    if (qty <= 0) continue;
    if (product.stock <= 0) {
      return `${product.name} is uitverkocht.`;
    }
    if (product.stock < qty) {
      return `Niet genoeg voorraad voor ${product.name}. Beschikbaar: ${product.stock}.`;
    }
  }
  return null;
}

function extractItemsFromMetadata(metadata) {
  if (!metadata) return [];
  const source = metadata.items ?? metadata;
  if (Array.isArray(source)) return source;
  if (typeof source === "string") {
    try {
      const parsed = JSON.parse(source);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function updateStockForItems(items) {
  if (!Array.isArray(items) || items.length === 0) return false;

  const state = readCatalogState();
  const { list } = state;
  if (!Array.isArray(list) || list.length === 0) return false;

  let changed = false;

  for (const item of items) {
    const id = String(item?.id || "");
    const qty = Math.max(0, Number(item?.qty || 0));
    if (!id || qty <= 0) continue;

    const entry = list.find((p) => String(p.id) === id);
    if (!entry) continue;

    const currentRaw = Number(entry.stock ?? 0);
    const current = Number.isFinite(currentRaw) ? currentRaw : 0;
    const next = Math.max(0, current - qty);

    if (next !== current) {
      entry.stock = next;
      changed = true;
    }
  }

  if (changed) {
    try {
      writeCatalogState(state);
    } catch (e) {
      console.error("Voorraad opslaan mislukt:", e);
    }
  }

  return changed;
}

/* ------------ Email functions ------------ */
function formatEUR(n) {
  return new Intl.NumberFormat("nl-NL", {
    style: "currency",
    currency: "EUR",
  }).format(n);
}

function generateOrderEmailHTML(orderData) {
  const {
    orderId,
    items = [],
    sender = {},
    discount = 0,
    shippingCost = 0,
    giftWrapCost = 0,
    subTotal = 0,
    total = 0,
  } = orderData;

  const itemsHTML = items
    .map((item) => {
      const productName = item.name || item.id;
      const qty = item.qty || 1;
      const price = item.price || 0;
      const lineTotal = price * qty;
      const imageUrl = item.image || null;
      const imageHTML = imageUrl
        ? `<img src="${imageUrl}" alt="${productName}" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px; margin-right: 12px;" />`
        : `<div style="width: 80px; height: 80px; background: #f0f0f0; border-radius: 8px; margin-right: 12px; display: flex; align-items: center; justify-content: center; color: #999; font-size: 12px;">Geen afbeelding</div>`;
      
      return `
        <tr>
          <td style="padding: 16px; border-bottom: 1px solid #eee; vertical-align: top;">
            <div style="display: flex; align-items: center;">
              ${imageHTML}
              <div>
                <div style="font-weight: 600; margin-bottom: 4px;">${productName}</div>
                ${item.note ? `<div style="font-size: 12px; color: #666; margin-top: 4px;">Notitie: ${item.note}</div>` : ""}
              </div>
            </div>
          </td>
          <td style="padding: 16px; border-bottom: 1px solid #eee; text-align: center; vertical-align: top;">${qty}</td>
          <td style="padding: 16px; border-bottom: 1px solid #eee; text-align: right; vertical-align: top; font-weight: 600;">${formatEUR(lineTotal)}</td>
        </tr>
      `;
    })
    .join("");

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
      line-height: 1.6; 
      color: #333; 
      margin: 0; 
      padding: 0; 
      background-color: #f5f5f5;
    }
    .email-container { 
      max-width: 600px; 
      margin: 0 auto; 
      background: #ffffff;
    }
    .header { 
      background: linear-gradient(135deg, #ff6b9d 0%, #ff8fab 100%); 
      padding: 40px 20px; 
      text-align: center;
      color: white;
    }
    .header h1 { 
      margin: 0; 
      font-size: 28px; 
      font-weight: 700;
    }
    .header p { 
      margin: 10px 0 0 0; 
      font-size: 16px; 
      opacity: 0.95;
    }
    .content { 
      padding: 30px 20px; 
    }
    .order-number {
      background: #f8f9fa;
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 14px;
    }
    .order-number strong {
      color: #ff6b9d;
      font-size: 16px;
    }
    table { 
      width: 100%; 
      border-collapse: collapse; 
      margin: 24px 0; 
      background: #fff;
    }
    table thead {
      background: #f8f9fa;
    }
    table th {
      padding: 12px 16px;
      text-align: left;
      font-weight: 600;
      font-size: 14px;
      color: #333;
      border-bottom: 2px solid #dee2e6;
    }
    table th:last-child {
      text-align: right;
    }
    table th:nth-child(2) {
      text-align: center;
    }
    .total-section {
      margin-top: 24px;
      padding-top: 24px;
      border-top: 2px solid #dee2e6;
    }
    .total-row { 
      font-weight: 600; 
      font-size: 16px;
      padding: 8px 0;
    }
    .total-row.final {
      font-size: 20px;
      font-weight: 700;
      color: #ff6b9d;
      padding-top: 16px;
      border-top: 2px solid #dee2e6;
      margin-top: 8px;
    }
    .discount-row {
      color: #28a745;
    }
    .footer { 
      margin-top: 40px; 
      padding-top: 24px; 
      border-top: 1px solid #eee; 
      font-size: 14px; 
      color: #666; 
      text-align: center;
      background: #f8f9fa;
      padding: 24px 20px;
    }
    .sender-info {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 8px;
      margin-top: 24px;
    }
    .sender-info h3 {
      margin: 0 0 12px 0;
      font-size: 16px;
      color: #333;
    }
    .sender-info p {
      margin: 4px 0;
      font-size: 14px;
      line-height: 1.8;
    }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="header">
      <h1>Bedankt voor je bestelling!</h1>
      <p>We gaan aan de slag!</p>
    </div>
    <div class="content">
      <div class="order-number">
        <strong>Ordernummer:</strong> ${orderId}
      </div>
      
      <h2 style="margin: 0 0 16px 0; font-size: 20px; color: #333;">Besteloverzicht</h2>
      
      <table>
        <thead>
          <tr>
            <th>Product</th>
            <th>Aantal</th>
            <th>Prijs</th>
          </tr>
        </thead>
        <tbody>
          ${itemsHTML}
        </tbody>
      </table>
      
      <div class="total-section">
        <div class="total-row" style="text-align: right;">
          <span style="float: left;">Subtotaal:</span>
          <span>${formatEUR(subTotal)}</span>
        </div>
        ${discount > 0 ? `
        <div class="total-row discount-row" style="text-align: right;">
          <span style="float: left;">Bulk korting:</span>
          <span>-${formatEUR(discount)}</span>
        </div>
        ` : ""}
        <div class="total-row" style="text-align: right;">
          <span style="float: left;">Verzendkosten:</span>
          <span>${formatEUR(shippingCost)}</span>
        </div>
        ${giftWrapCost > 0 ? `
        <div class="total-row" style="text-align: right;">
          <span style="float: left;">Cadeau inpakken:</span>
          <span>${formatEUR(giftWrapCost)}</span>
        </div>
        ` : ""}
        <div class="total-row final" style="text-align: right;">
          <span style="float: left;">Totaal:</span>
          <span>${formatEUR(total)}</span>
        </div>
      </div>
      
      ${sender.email ? `
      <div class="sender-info">
        <h3>Afzender gegevens</h3>
        <p>
          <strong>${sender.firstName || ""} ${sender.lastName || ""}</strong><br>
          ${sender.streetAndNumber || sender.street || ""} ${sender.number || ""}<br>
          ${sender.postalCode || ""} ${sender.city || ""}<br>
          ${sender.country || ""}<br>
          <br>
          E-mail: ${sender.email}<br>
          ${sender.phone ? `Telefoon: ${sender.phone}` : ""}
        </p>
      </div>
      ` : ""}
    </div>
    <div class="footer">
      <p style="margin: 0 0 8px 0;"><strong>We gaan aan de slag met je bestelling!</strong></p>
      <p style="margin: 0;">Met vriendelijke groet,<br>Het Momena team</p>
    </div>
  </div>
</body>
</html>
  `;
}

function generateOrderEmailText(orderData) {
  const {
    orderId,
    items = [],
    sender = {},
    discount = 0,
    shippingCost = 0,
    giftWrapCost = 0,
    subTotal = 0,
    total = 0,
  } = orderData;

  let text = `Bedankt voor je bestelling!\n\n`;
  text += `We gaan aan de slag!\n\n`;
  text += `Ordernummer: ${orderId}\n\n`;
  text += `Besteloverzicht:\n`;
  text += `${"=".repeat(60)}\n\n`;

  items.forEach((item) => {
    const productName = item.name || item.id;
    const qty = item.qty || 1;
    const price = item.price || 0;
    const lineTotal = price * qty;
    text += `${productName}${item.note ? ` (Notitie: ${item.note})` : ""}\n`;
    text += `  Aantal: ${qty} x ${formatEUR(price)} = ${formatEUR(lineTotal)}\n\n`;
  });

  text += `${"-".repeat(60)}\n`;
  text += `Subtotaal: ${formatEUR(subTotal)}\n`;
  if (discount > 0) {
    text += `Bulk korting: -${formatEUR(discount)}\n`;
  }
  text += `Verzendkosten: ${formatEUR(shippingCost)}\n`;
  if (giftWrapCost > 0) {
    text += `Cadeau inpakken: ${formatEUR(giftWrapCost)}\n`;
  }
  text += `Totaal: ${formatEUR(total)}\n\n`;

  if (sender.email) {
    text += `Afzender gegevens:\n`;
    text += `${"-".repeat(60)}\n`;
    text += `${sender.firstName || ""} ${sender.lastName || ""}\n`;
    text += `${sender.streetAndNumber || sender.street || ""} ${sender.number || ""}\n`;
    text += `${sender.postalCode || ""} ${sender.city || ""}\n`;
    text += `${sender.country || ""}\n`;
    text += `E-mail: ${sender.email}\n`;
    if (sender.phone) {
      text += `Telefoon: ${sender.phone}\n`;
    }
    text += `\n`;
  }

  text += `We gaan aan de slag met je bestelling!\n`;
  text += `Met vriendelijke groet,\nHet Momena team`;

  return text;
}

async function sendOrderConfirmationEmail(orderData, recipientEmail) {
  if (!recipientEmail) {
    console.warn("⚠️ Geen e-mailadres gevonden voor order bevestiging");
    return false;
  }

  if (!SENDGRID_API_KEY) {
    console.warn("⚠️ SENDGRID_API_KEY niet ingesteld - email wordt niet verstuurd");
    console.log("📧 Email zou worden verstuurd naar:", recipientEmail);
    console.log("📧 Order ID:", orderData.orderId);
    return false;
  }

  try {
    const html = generateOrderEmailHTML(orderData);
    const text = generateOrderEmailText(orderData);

    const sendgridResponse = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SENDGRID_API_KEY}`,
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: [{ email: recipientEmail }],
          },
        ],
        from: { email: EMAIL_FROM, name: "Momena" },
        subject: `Bestelbevestiging ${orderData.orderId}`,
        content: [
          { type: "text/plain", value: text },
          { type: "text/html", value: html },
        ],
      }),
    });

    if (!sendgridResponse.ok) {
      const errorText = await sendgridResponse.text();
      throw new Error(`SendGrid API error: ${sendgridResponse.status} - ${errorText}`);
    }

    console.log(`✅ Email verstuurd naar ${recipientEmail} voor order ${orderData.orderId}`);
    return true;
  } catch (e) {
    console.error(`❌ Fout bij versturen email naar ${recipientEmail}:`, e.message);
    return false;
  }
}

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();
const stockAdjustedOrders = new Set();
const emailsSent = new Set(); // Track welke orders al een email hebben gehad

/* ------------ Users (DB via Prisma) ------------ */
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
    req.user = data;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
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

app.get("/api/products", (_req, res) => {
  const catalog = loadCatalog();
  res.set("Cache-Control", "no-store");
  res.json({ products: catalog });
});

/* --------- AUTH: signup/login/me/logout + profiel opslaan ---------- */
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, profile } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email en password verplicht" });

    const exists = await findUserByEmail(email);
    if (exists) return res.status(400).json({ error: "Account bestaat al" });

    const user = await createUser({ email, password, profile });

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

/* --------- AUTH: Forgot Password / Reset Password ---------- */

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email, resetPageUrl } = req.body || {};
    if (!email || !resetPageUrl) {
      return res.status(400).json({ error: "E-mail en reset URL verplicht" });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      // Stuur altijd een succesbericht om e-mail enumeratie te voorkomen
      return res.json({
        ok: true,
        message: "Als het account bestaat, is er een e-mail verstuurd.",
      });
    }

    // 1. Genereer token en vervaltijd (bijv. 1 uur)
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 uur

    // 2. Sla token op in database
    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken, resetTokenExpires },
    });

    // 3. Stuur e-mail met reset link
    const resetLink = `${resetPageUrl}?token=${resetToken}&email=${encodeURIComponent(
      email
    )}`;
    
    // --- HIER MOET U UW E-MAIL LOGICA PLAATSEN ---
    // Voor nu loggen we de link:
    console.log(`🔑 Wachtwoord Reset Token voor ${email}: ${resetToken}`);
    console.log(`📧 Reset Link: ${resetLink}`);
    // ----------------------------------------------

    res.json({
      ok: true,
      message: "Als het account bestaat, is er een e-mail verstuurd.",
    });
  } catch (e) {
    console.error("Forgot password error:", e);
    res.status(500).json({ error: "Reset verzoek mislukt" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, email, newPassword } = req.body || {};
    if (!token || !email || !newPassword) {
      return res
        .status(400)
        .json({ error: "Token, e-mail en wachtwoord zijn vereist" });
    }

    const user = await findUserByEmail(email);

    // 1. Controleer of gebruiker bestaat, token klopt en niet verlopen is
    if (
      !user ||
      user.resetToken !== token ||
      (user.resetTokenExpires && user.resetTokenExpires < new Date())
    ) {
      return res
        .status(400)
        .json({ error: "Ongeldige of verlopen reset-link" });
    }

    // 2. Hash het nieuwe wachtwoord
    const newHash = await bcrypt.hash(String(newPassword), 10);

    // 3. Update het wachtwoord en wis de reset-velden
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: newHash,
        resetToken: null, // Wis de token na gebruik
        resetTokenExpires: null, // Wis de vervaltijd
      },
    });

    res.json({ ok: true, message: "Wachtwoord succesvol gewijzigd" });
  } catch (e) {
    console.error("Reset password error:", e);
    res.status(500).json({ error: "Wachtwoord reset mislukt" });
  }
});


/* --------- Checkout ---------- */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const sender = req.body?.sender || null;
    const senderPrefs = req.body?.senderPrefs || {};
    const orderId = req.body?.orderId || `order_${Date.now()}`;
    const discount = Number(req.body?.discount || 0);
    const shippingCost = Number(req.body?.shippingCost || 0);
    const giftWrapCost = Number(req.body?.giftWrapCost || 0);

    const catalog = loadCatalog();
    const subtotal = calcTotal(items, catalog);

    if (!subtotal || subtotal <= 0) {
      return res.status(400).json({ error: "Cart is empty or invalid" });
    }

    const stockError = validateStock(items, catalog);
    if (stockError) {
      return res.status(400).json({ error: stockError });
    }

    // Bereken totaal: subtotaal - korting + verzendkosten + cadeau inpakken
    const total = Math.max(0, subtotal - discount + shippingCost + giftWrapCost);

    const description = `Order ${orderId} – ${items.length} items`;

    const primaryFrontendUrl = getPrimaryFrontendUrl();
    const payment = await mollie("/payments", "POST", {
      amount: { currency: "EUR", value: total.toFixed(2) },
      description,
      redirectUrl: `${primaryFrontendUrl}/bedankt?orderId=${encodeURIComponent(
        orderId
      )}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      metadata: { orderId, items, sender, senderPrefs, discount, shippingCost, giftWrapCost },
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

      if (
        (status === "paid" || status === "authorized") &&
        !stockAdjustedOrders.has(orderId)
      ) {
        const items = extractItemsFromMetadata(payment.metadata);
        const changed = updateStockForItems(items);
        if (changed) {
          console.log(`📦 Voorraad bijgewerkt voor ${orderId}`);
        }
        stockAdjustedOrders.add(orderId);
      }

      // Verstuur orderbevestiging emails wanneer betaling is betaald
      if (status === "paid" && !emailsSent.has(orderId)) {
        try {
          const metadata = payment.metadata || {};
          const items = extractItemsFromMetadata(metadata);
          const catalog = loadCatalog();

          // Verrijk items met product informatie
          const enrichedItems = items.map((item) => {
            const product = catalog.find((p) => p.id === item.id);
            const qty = Number(item.qty || 1);
            const price = product?.price || 0;
            return {
              id: item.id,
              name: product?.name || item.id,
              price: price,
              image: product?.image || null,
              qty: qty,
              note: item.note || undefined,
            };
          });

          // Bereken totalen
          const subTotal = enrichedItems.reduce((sum, item) => sum + item.price * item.qty, 0);
          const discount = Number(metadata.discount || 0);
          const shippingCost = Number(metadata.shippingCost || 0);
          const giftWrapCost = Number(metadata.giftWrapCost || 0);
          const total = Math.max(0, subTotal - discount + shippingCost + giftWrapCost);

          const orderData = {
            orderId: metadata.orderId || orderId,
            items: enrichedItems,
            sender: metadata.sender || {},
            discount: discount,
            shippingCost: shippingCost,
            giftWrapCost: giftWrapCost,
            subTotal: subTotal,
            total: total,
          };

          // Verstuur email naar klant
          const customerEmail = metadata.sender?.email;
          if (customerEmail) {
            const emailSent = await sendOrderConfirmationEmail(orderData, customerEmail);
            if (emailSent) {
              console.log(`✅ Email verstuurd naar klant: ${customerEmail}`);
            }
          }

          // Verstuur email naar bestellingen@momena.nl
          const adminEmailSent = await sendOrderConfirmationEmail(orderData, ORDER_EMAIL_TO);
          if (adminEmailSent) {
            console.log(`✅ Email verstuurd naar ${ORDER_EMAIL_TO}`);
          }

          if (customerEmail || adminEmailSent) {
            emailsSent.add(orderId);
          }
        } catch (emailError) {
          console.error(`❌ Fout bij versturen emails voor order ${orderId}:`, emailError);
        }
      }
    }

    console.log(`🔔 ${orderId || "unknown order"} -> ${status}`);
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
  console.log(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(", ") || "none"}`);
  console.log(`Primary frontend URL: ${getPrimaryFrontendUrl()}`);
  console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
});
