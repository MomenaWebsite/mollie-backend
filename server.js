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
// LET OP: U moet de logica voor e-mail verzenden implementeren,
// of op zijn minst een service zoals Nodemailer of SendGrid instellen.
// ZONDER E-MAIL IMPLEMENTATIE zal de link alleen in uw console verschijnen.
const MOLLIE_API_KEY = process.env.MOLLIE_API_KEY;
const POSTNL_API_KEY = process.env.POSTNL_API_KEY;
const EMAIL_PASS = process.env.EMAIL_PASS; // SendGrid API key
const EMAIL_USER = process.env.EMAIL_USER || "apikey";
const EMAIL_HOST = process.env.EMAIL_HOST || "smtp.sendgrid.net";
const EMAIL_PORT = process.env.EMAIL_PORT || "587";
const EMAIL_SENDER_NAME = process.env.EMAIL_SENDER_NAME || "Momona";
const EMAIL_FROM = process.env.EMAIL_FROM || "info@momena.nl"; // Geverifieerd e-mailadres in SendGrid
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-env";

if (!MOLLIE_API_KEY) console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!POSTNL_API_KEY) console.warn("⚠️ Missing POSTNL_API_KEY");
if (!EMAIL_PASS) console.warn("⚠️ Missing EMAIL_PASS (SendGrid API key)");
console.log(`📧 E-mail wordt verzonden vanaf: ${EMAIL_FROM} (zorg dat dit e-mailadres geverifieerd is in SendGrid)`);
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

  const weightRaw = Number(p.weight ?? 50); // gram, standaard 50g
  const weight = Number.isFinite(weightRaw)
    ? Math.max(1, Math.floor(weightRaw))
    : 50;

  return {
    id: String(p.id),
    name: String(p.name),
    price,
    image: p.image || undefined,
    stock,
    weight,
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

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();
const stockAdjustedOrders = new Set();
const emailsSentOrders = new Set(); // Voorkom dat e-mails meerdere keren worden verstuurd

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

// SendGrid helper: stuur e-mail via SendGrid API
async function sendEmailViaSendGrid({ to, subject, html, text }) {
  if (!EMAIL_PASS) {
    throw new Error("EMAIL_PASS (SendGrid API key) is niet geconfigureerd");
  }

  if (!EMAIL_FROM || EMAIL_FROM.trim() === "") {
    throw new Error("EMAIL_FROM is niet geconfigureerd. Dit moet een geverifieerd e-mailadres zijn in je SendGrid account. Zie: https://sendgrid.com/docs/for-developers/sending-email/sender-identity/");
  }

  try {
    const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${EMAIL_PASS}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: [{ email: to }],
            subject: subject,
          },
        ],
        from: {
          email: EMAIL_FROM,
          name: EMAIL_SENDER_NAME || "Momona",
        },
        content: [
          {
            type: "text/plain",
            value: text || html?.replace(/<[^>]*>/g, "") || "",
          },
          {
            type: "text/html",
            value: html || text || "",
          },
        ],
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `SendGrid API error: ${response.status}`;
      
      try {
        const errorData = JSON.parse(errorText);
        if (errorData.errors && errorData.errors.length > 0) {
          const firstError = errorData.errors[0];
          errorMessage = `SendGrid API error: ${firstError.message || errorMessage}`;
          
          // Specifieke error voor niet-geverifieerd e-mailadres
          if (firstError.message && firstError.message.includes("verified Sender Identity")) {
            errorMessage = `SendGrid Error: Het e-mailadres "${EMAIL_FROM}" is niet geverifieerd in je SendGrid account. Verifieer dit e-mailadres eerst in je SendGrid dashboard. Zie: https://sendgrid.com/docs/for-developers/sending-email/sender-identity/`;
          }
        }
      } catch (parseError) {
        // Als parsing faalt, gebruik de originele error text
        errorMessage = `SendGrid API error: ${response.status} - ${errorText}`;
      }
      
      console.error("SendGrid API error:", response.status, errorText);
      throw new Error(errorMessage);
    }

    return true;
  } catch (e) {
    console.error("SendGrid e-mail verzenden mislukt:", e);
    throw e;
  }
}

// Functie om orderbevestigings e-mails te versturen
async function sendOrderConfirmationEmails({ orderId, items, sender, total, discount = 0, shippingCost = 0 }) {
  if (!EMAIL_PASS || !EMAIL_FROM) {
    console.error("⚠️ E-mail configuratie ontbreekt, kan geen orderbevestiging versturen");
    return;
  }

  const catalog = loadCatalog();
  const orderDate = new Date().toLocaleDateString("nl-NL", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  // Maak een lijst van bestelde items met alle details
  const itemsList = items
    .map((item) => {
      const product = catalog.find((p) => p.id === item.id);
      const productName = product?.name || item.id;
      const productPrice = product?.price || 0;
      const productId = item.id || "";
      const productImage = product?.image || "";
      const qty = item.qty || 1;
      const itemTotal = productPrice * qty;
      return {
        id: productId,
        name: productName,
        image: productImage,
        qty,
        price: productPrice,
        total: itemTotal,
        note: item.note || "",
        sendNow: item.sendNow || false,
        shipping: item.shipping || null,
        attachedCandles: item.attachedCandles || [],
      };
    })
    .filter((item) => item.qty > 0);

  const subtotal = itemsList.reduce((sum, item) => sum + item.total, 0);
  const finalTotal = subtotal - discount + shippingCost;

  // HTML template voor klant
  const customerEmailHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Orderbevestiging</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #333;">Bedankt voor je bestelling!</h2>
      <p>Beste ${sender?.firstName || ""} ${sender?.lastName || ""},</p>
      <p>We hebben je bestelling ontvangen en gaan er direct mee aan de slag.</p>
      
      <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 0;"><strong>Ordernummer:</strong> ${orderId}</p>
        <p style="margin: 5px 0 0 0;"><strong>Besteldatum:</strong> ${orderDate}</p>
      </div>

      <h3 style="color: #333; margin-top: 30px;">Je bestelling:</h3>
      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <thead>
          <tr style="background: #f5f5f5;">
            <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Product</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Aantal</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Prijs</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Totaal</th>
          </tr>
        </thead>
        <tbody>
          ${itemsList
            .map(
              (item) => {
                // Haal productnamen op voor attached candles
                const attachedCandlesInfo = item.attachedCandles && item.attachedCandles.length > 0
                  ? item.attachedCandles.map((c) => {
                      const candleProduct = catalog.find((p) => p.id === c.id);
                      const candleName = candleProduct?.name || c.id;
                      return `${c.qty}x ${candleName}`;
                    }).join(", ")
                  : "";
                
                return `
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee;">
                ${item.image ? `<img src="${item.image}" alt="${item.name}" style="width: 60px; height: 60px; object-fit: cover; border-radius: 8px; margin-right: 10px; vertical-align: middle; float: left;" />` : ""}
                <div style="${item.image ? "margin-left: 70px;" : ""}">
                  <strong>${item.name}</strong>
                  <br><small style="color: #999;">Product ID: ${item.id}</small>
                  ${item.note ? `<br><br><small style="color: #666;"><strong>Bericht op kaart:</strong> ${item.note}</small>` : ""}
                  ${item.sendNow && item.shipping ? `
                    <br><br><small style="color: #666;"><strong>Direct verzenden naar:</strong><br>
                      ${item.shipping.firstName || ""} ${item.shipping.lastName || ""}<br>
                      ${item.shipping.streetAndNumber || ""}<br>
                      ${item.shipping.postalCode || ""} ${item.shipping.city || ""}<br>
                      ${item.shipping.country || ""}
                      ${item.shipping.deliveryDate ? `<br><strong>Gewenste aankomstdatum:</strong> ${item.shipping.deliveryDate}` : ""}
                    </small>
                  ` : ""}
                  ${attachedCandlesInfo ? `<br><br><small style="color: #666;"><strong>Gekoppelde kaars(en):</strong> ${attachedCandlesInfo}</small>` : ""}
                </div>
                <div style="clear: both;"></div>
              </td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">${item.qty}</td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">€${item.price.toFixed(2)}</td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">€${item.total.toFixed(2)}</td>
            </tr>
          `;
              }
            )
            .join("")}
        </tbody>
      </table>

      <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <table style="width: 100%;">
          <tr>
            <td style="padding: 5px 0;"><strong>Subtotaal:</strong></td>
            <td style="text-align: right; padding: 5px 0;">€${subtotal.toFixed(2)}</td>
          </tr>
          ${discount > 0 ? `<tr><td style="padding: 5px 0;"><strong>Korting:</strong></td><td style="text-align: right; padding: 5px 0; color: #0a7f2e;">-€${discount.toFixed(2)}</td></tr>` : ""}
          ${shippingCost > 0 ? `<tr><td style="padding: 5px 0;"><strong>Verzendkosten:</strong></td><td style="text-align: right; padding: 5px 0;">€${shippingCost.toFixed(2)}</td></tr>` : ""}
          <tr style="border-top: 2px solid #333;">
            <td style="padding: 10px 0 5px 0;"><strong>Totaal:</strong></td>
            <td style="text-align: right; padding: 10px 0 5px 0; font-size: 18px; font-weight: bold;">€${finalTotal.toFixed(2)}</td>
          </tr>
        </table>
      </div>

      <h3 style="color: #333; margin-top: 30px;">Afleveradres:</h3>
      <p>
        ${sender?.firstName || ""} ${sender?.lastName || ""}<br>
        ${sender?.streetAndNumber || `${sender?.street || ""} ${sender?.number || ""}`.trim()}<br>
        ${sender?.postalCode || ""} ${sender?.city || ""}<br>
        ${sender?.country || ""}
      </p>

      <p style="margin-top: 30px; color: #666; font-size: 12px;">
        Je ontvangt een aparte e-mail zodra je bestelling is verzonden.
      </p>
    </body>
    </html>
  `;

  // HTML template voor bestellingen@momena.nl (admin)
  const adminEmailHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Nieuwe bestelling - ${orderId}</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #333;">Nieuwe bestelling ontvangen</h2>
      
      <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 0;"><strong>Ordernummer:</strong> ${orderId}</p>
        <p style="margin: 5px 0 0 0;"><strong>Besteldatum:</strong> ${orderDate}</p>
        <p style="margin: 5px 0 0 0;"><strong>Totaalbedrag:</strong> €${finalTotal.toFixed(2)}</p>
      </div>

      <h3 style="color: #333; margin-top: 30px;">Afzender gegevens:</h3>
      <p>
        <strong>Naam:</strong> ${sender?.firstName || ""} ${sender?.lastName || ""}<br>
        <strong>E-mail:</strong> ${sender?.email || ""}<br>
        <strong>Telefoon:</strong> ${sender?.phone || ""}<br>
        <strong>Adres:</strong> ${sender?.streetAndNumber || `${sender?.street || ""} ${sender?.number || ""}`.trim()}<br>
        <strong>Postcode:</strong> ${sender?.postalCode || ""}<br>
        <strong>Plaats:</strong> ${sender?.city || ""}<br>
        <strong>Land:</strong> ${sender?.country || ""}
      </p>

      <h3 style="color: #333; margin-top: 30px;">Bestelde producten:</h3>
      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <thead>
          <tr style="background: #f5f5f5;">
            <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Product</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Aantal</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Prijs</th>
            <th style="padding: 10px; text-align: right; border-bottom: 2px solid #ddd;">Totaal</th>
          </tr>
        </thead>
        <tbody>
          ${itemsList
            .map(
              (item) => {
                // Haal productnamen op voor attached candles
                const attachedCandlesInfo = item.attachedCandles && item.attachedCandles.length > 0
                  ? item.attachedCandles.map((c) => {
                      const candleProduct = catalog.find((p) => p.id === c.id);
                      const candleName = candleProduct?.name || c.id;
                      return `${c.qty}x ${candleName}`;
                    }).join(", ")
                  : "";
                
                return `
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee;">
                ${item.image ? `<img src="${item.image}" alt="${item.name}" style="width: 60px; height: 60px; object-fit: cover; border-radius: 8px; margin-right: 10px; vertical-align: middle; float: left;" />` : ""}
                <div style="${item.image ? "margin-left: 70px;" : ""}">
                  <strong>${item.name}</strong>
                  <br><small style="color: #999;">Product ID: ${item.id}</small>
                  ${item.note ? `<br><br><small style="color: #666;"><strong>Bericht op kaart:</strong> ${item.note}</small>` : ""}
                  ${item.sendNow && item.shipping ? `
                    <br><br><small style="color: #666;"><strong>Direct verzenden naar:</strong><br>
                      ${item.shipping.firstName || ""} ${item.shipping.lastName || ""}<br>
                      ${item.shipping.streetAndNumber || ""}<br>
                      ${item.shipping.postalCode || ""} ${item.shipping.city || ""}<br>
                      ${item.shipping.country || ""}
                      ${item.shipping.deliveryDate ? `<br><strong>Gewenste aankomstdatum:</strong> ${item.shipping.deliveryDate}` : ""}
                    </small>
                  ` : ""}
                  ${attachedCandlesInfo ? `<br><br><small style="color: #666;"><strong>Gekoppelde kaars(en):</strong> ${attachedCandlesInfo}</small>` : ""}
                </div>
                <div style="clear: both;"></div>
              </td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">${item.qty}</td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">€${item.price.toFixed(2)}</td>
              <td style="padding: 10px; text-align: right; border-bottom: 1px solid #eee; vertical-align: top;">€${item.total.toFixed(2)}</td>
            </tr>
          `;
              }
            )
            .join("")}
        </tbody>
      </table>

      <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <table style="width: 100%;">
          <tr>
            <td style="padding: 5px 0;"><strong>Subtotaal:</strong></td>
            <td style="text-align: right; padding: 5px 0;">€${subtotal.toFixed(2)}</td>
          </tr>
          ${discount > 0 ? `<tr><td style="padding: 5px 0;"><strong>Korting:</strong></td><td style="text-align: right; padding: 5px 0; color: #0a7f2e;">-€${discount.toFixed(2)}</td></tr>` : ""}
          ${shippingCost > 0 ? `<tr><td style="padding: 5px 0;"><strong>Verzendkosten:</strong></td><td style="text-align: right; padding: 5px 0;">€${shippingCost.toFixed(2)}</td></tr>` : ""}
          <tr style="border-top: 2px solid #333;">
            <td style="padding: 10px 0 5px 0;"><strong>Totaal:</strong></td>
            <td style="text-align: right; padding: 10px 0 5px 0; font-size: 18px; font-weight: bold;">€${finalTotal.toFixed(2)}</td>
          </tr>
        </table>
      </div>
    </body>
    </html>
  `;

  // Maak tekstversie van e-mail met alle productinformatie
  const customerEmailText = `Bedankt voor je bestelling!

Ordernummer: ${orderId}
Besteldatum: ${orderDate}

Je bestelling:
${itemsList.map((item) => {
  const attachedCandlesInfo = item.attachedCandles && item.attachedCandles.length > 0
    ? item.attachedCandles.map((c) => {
        const candleProduct = catalog.find((p) => p.id === c.id);
        const candleName = candleProduct?.name || c.id;
        return `${c.qty}x ${candleName}`;
      }).join(", ")
    : "";
  
  let itemText = `- ${item.name} (ID: ${item.id})\n  Aantal: ${item.qty} x €${item.price.toFixed(2)} = €${item.total.toFixed(2)}`;
  if (item.note) itemText += `\n  Bericht op kaart: ${item.note}`;
  if (item.sendNow && item.shipping) {
    itemText += `\n  Direct verzenden naar:\n    ${item.shipping.firstName || ""} ${item.shipping.lastName || ""}\n    ${item.shipping.streetAndNumber || ""}\n    ${item.shipping.postalCode || ""} ${item.shipping.city || ""}\n    ${item.shipping.country || ""}`;
    if (item.shipping.deliveryDate) itemText += `\n    Gewenste aankomstdatum: ${item.shipping.deliveryDate}`;
  }
  if (attachedCandlesInfo) itemText += `\n  Gekoppelde kaars(en): ${attachedCandlesInfo}`;
  return itemText;
}).join("\n\n")}

Subtotaal: €${subtotal.toFixed(2)}
${discount > 0 ? `Korting: -€${discount.toFixed(2)}\n` : ""}${shippingCost > 0 ? `Verzendkosten: €${shippingCost.toFixed(2)}\n` : ""}Totaal: €${finalTotal.toFixed(2)}

Afleveradres:
${sender?.firstName || ""} ${sender?.lastName || ""}
${sender?.streetAndNumber || `${sender?.street || ""} ${sender?.number || ""}`.trim()}
${sender?.postalCode || ""} ${sender?.city || ""}
${sender?.country || ""}

Je ontvangt een aparte e-mail zodra je bestelling is verzonden.`;

  const adminEmailText = `Nieuwe bestelling ontvangen

Ordernummer: ${orderId}
Besteldatum: ${orderDate}
Totaalbedrag: €${finalTotal.toFixed(2)}

Afzender gegevens:
Naam: ${sender?.firstName || ""} ${sender?.lastName || ""}
E-mail: ${sender?.email || ""}
Telefoon: ${sender?.phone || ""}
Adres: ${sender?.streetAndNumber || `${sender?.street || ""} ${sender?.number || ""}`.trim()}
Postcode: ${sender?.postalCode || ""}
Plaats: ${sender?.city || ""}
Land: ${sender?.country || ""}

Bestelde producten:
${itemsList.map((item) => {
  const attachedCandlesInfo = item.attachedCandles && item.attachedCandles.length > 0
    ? item.attachedCandles.map((c) => {
        const candleProduct = catalog.find((p) => p.id === c.id);
        const candleName = candleProduct?.name || c.id;
        return `${c.qty}x ${candleName}`;
      }).join(", ")
    : "";
  
  let itemText = `- ${item.name} (ID: ${item.id})\n  Aantal: ${item.qty} x €${item.price.toFixed(2)} = €${item.total.toFixed(2)}`;
  if (item.note) itemText += `\n  Bericht op kaart: ${item.note}`;
  if (item.sendNow && item.shipping) {
    itemText += `\n  Direct verzenden naar:\n    ${item.shipping.firstName || ""} ${item.shipping.lastName || ""}\n    ${item.shipping.streetAndNumber || ""}\n    ${item.shipping.postalCode || ""} ${item.shipping.city || ""}\n    ${item.shipping.country || ""}`;
    if (item.shipping.deliveryDate) itemText += `\n    Gewenste aankomstdatum: ${item.shipping.deliveryDate}`;
  }
  if (attachedCandlesInfo) itemText += `\n  Gekoppelde kaars(en): ${attachedCandlesInfo}`;
  return itemText;
}).join("\n\n")}

Subtotaal: €${subtotal.toFixed(2)}
${discount > 0 ? `Korting: -€${discount.toFixed(2)}\n` : ""}${shippingCost > 0 ? `Verzendkosten: €${shippingCost.toFixed(2)}\n` : ""}Totaal: €${finalTotal.toFixed(2)}`;

  // Stuur e-mail naar klant
  if (sender?.email) {
    try {
      await sendEmailViaSendGrid({
        to: sender.email,
        subject: `Orderbevestiging - ${orderId}`,
        html: customerEmailHtml,
        text: customerEmailText,
      });
      console.log(`✅ Orderbevestiging verzonden naar klant: ${sender.email}`);
    } catch (emailError) {
      console.error(`❌ E-mail naar klant mislukt (${sender.email}):`, emailError);
    }
  }

  // Stuur e-mail naar bestellingen@momena.nl
  try {
    await sendEmailViaSendGrid({
      to: "bestellingen@momena.nl",
      subject: `Nieuwe bestelling - ${orderId}`,
      html: adminEmailHtml,
      text: adminEmailText,
    });
    console.log(`✅ Orderbevestiging verzonden naar bestellingen@momena.nl`);
  } catch (emailError) {
    console.error(`❌ E-mail naar bestellingen@momena.nl mislukt:`, emailError);
  }
}

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

    // 3. Stuur e-mail met reset link via SendGrid
    const resetLink = `${resetPageUrl}?token=${resetToken}&email=${encodeURIComponent(
      email
    )}`;
    
    try {
      await sendEmailViaSendGrid({
        to: email,
        subject: "Wachtwoord resetten",
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Wachtwoord resetten</title>
          </head>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Wachtwoord resetten</h2>
            <p>Beste gebruiker,</p>
            <p>U heeft een verzoek gedaan om uw wachtwoord te resetten. Klik op de onderstaande link om een nieuw wachtwoord in te stellen:</p>
            <p style="margin: 30px 0;">
              <a href="${resetLink}" style="background-color: #0070f3; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Wachtwoord resetten</a>
            </p>
            <p>Of kopieer en plak deze link in uw browser:</p>
            <p style="word-break: break-all; color: #666; font-size: 12px;">${resetLink}</p>
            <p style="margin-top: 30px; color: #666; font-size: 12px;">
              <strong>Let op:</strong> Deze link is 1 uur geldig. Als u dit verzoek niet heeft gedaan, kunt u deze e-mail negeren.
            </p>
            <p style="margin-top: 20px; color: #999; font-size: 11px;">
              Als de knop niet werkt, kopieer en plak de bovenstaande link in uw browser.
            </p>
          </body>
          </html>
        `,
        text: `
          Wachtwoord resetten
          
          Beste gebruiker,
          
          U heeft een verzoek gedaan om uw wachtwoord te resetten. Gebruik de onderstaande link om een nieuw wachtwoord in te stellen:
          
          ${resetLink}
          
          Let op: Deze link is 1 uur geldig. Als u dit verzoek niet heeft gedaan, kunt u deze e-mail negeren.
        `,
      });
      
      console.log(`✅ Wachtwoord reset e-mail verzonden naar ${email}`);
    } catch (emailError) {
      console.error("❌ E-mail verzenden mislukt:", emailError);
      // Stuur nog steeds een succesbericht om e-mail enumeratie te voorkomen
      // Maar log de fout voor debugging
    }

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

/* --------- PostNL Shipping ---------- */
// Bereken verzendkosten op basis van gewicht
app.post("/api/calculate-shipping", async (req, res) => {
	try {
		const { method, postalCode, city, country, items } = req.body || {};
		if (!method || !postalCode || !city) {
			return res.status(400).json({ error: "Verzendmethode, postcode en stad zijn verplicht" });
		}

		// Bereken totaal gewicht in gram
		const totalWeight = (items || []).reduce((sum, item) => {
			const itemWeight = Number(item.weight || 50); // gram, standaard 50g
			const qty = Number(item.qty || 0);
			return sum + (itemWeight * qty);
		}, 0);

		// PostNL Shipping API: Calculate Shipment
		// Gebruik PostNL API om verzendkosten te berekenen op basis van gewicht
		try {
			const calculateResponse = await fetch("https://api.postnl.nl/shipment/v2_2/calculate/shipment", {
				method: "POST",
				headers: {
					"apikey": POSTNL_API_KEY,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					Shipment: {
						Addresses: [
							{
								AddressType: "01", // Thuis
								Zipcode: postalCode.replace(/\s+/g, ""),
								City: city,
								Countrycode: (country || "NL").toUpperCase(),
							},
						],
						Dimension: {
							Weight: Math.max(100, Math.min(totalWeight, 30000)), // Min 100g, max 30kg
						},
						ProductCodeDelivery: "3085", // Thuis bezorgen
					},
				}),
			});

			if (calculateResponse.ok) {
				const calculateData = await calculateResponse.json();
				// PostNL API geeft verzendkosten terug in centen, converteren naar euro's
				const costInCents = Number(calculateData?.Amounts?.[0]?.Amount || 0);
				const costInEuros = costInCents / 100;
				return res.json({ cost: costInEuros > 0 ? costInEuros : 6.95 });
			} else {
				console.error("PostNL calculate API error:", await calculateResponse.text());
			}
		} catch (apiError) {
			console.error("PostNL API call mislukt:", apiError);
		}

		// Fallback: simpele berekening op basis van gewicht
		// Voor NL: €6.95 voor pakketten tot 2kg, daarna €0.50 per extra kg
		const weightInKg = totalWeight / 1000;
		let baseShippingCost = 6.95;
		if (weightInKg > 2) {
			baseShippingCost = 6.95 + ((weightInKg - 2) * 0.50);
		}
		
		res.json({ cost: Math.max(6.95, baseShippingCost) });
	} catch (e) {
		console.error("Verzendkosten berekenen mislukt:", e);
		res.status(500).json({ error: "Kon verzendkosten niet berekenen" });
	}
});

// PostNL helper: maak shipment aan
async function createPostNLShipment(shipmentData) {
	try {
		// PostNL Shipping API endpoint
		const response = await fetch("https://api.postnl.nl/shipment/v2_2/shipment", {
			method: "POST",
			headers: {
				"apikey": POSTNL_API_KEY,
				"Content-Type": "application/json",
			},
			body: JSON.stringify(shipmentData),
		});
		
		if (!response.ok) {
			const text = await response.text();
			throw new Error(`PostNL API error: ${response.status} - ${text}`);
		}
		
		return await response.json();
	} catch (e) {
		console.error("PostNL shipment creation mislukt:", e);
		throw e;
	}
}

// PostNL helper: genereer barcodelabels voor een bestelling
async function generatePostNLLabels({ orderId, sender, items, shippingAddresses = [] }) {
	if (!POSTNL_API_KEY) {
		console.error("⚠️ POSTNL_API_KEY ontbreekt, kan geen labels genereren");
		return null;
	}

	try {
		const catalog = loadCatalog();
		
		// Bereken totaal gewicht in gram
		const totalWeight = items.reduce((sum, item) => {
			const product = catalog.find((p) => p.id === item.id);
			const itemWeight = Number(product?.weight || 50); // gram, standaard 50g
			const qty = Number(item.qty || 0);
			return sum + (itemWeight * qty);
		}, 0);

		// Maak shipment data voor PostNL
		const shipmentData = {
			Shipments: [
				{
					Addresses: [
						{
							AddressType: "01", // Thuis
							FirstName: sender?.firstName || "",
							Name: sender?.lastName || "",
							Street: sender?.street || "",
							HouseNr: sender?.number || "",
							HouseNrExt: "",
							Zipcode: sender?.postalCode?.replace(/\s+/g, "") || "",
							City: sender?.city || "",
							Countrycode: (sender?.country || "NL").toUpperCase(),
						},
					],
					Dimension: {
						Weight: Math.max(100, Math.min(totalWeight, 30000)), // Min 100g, max 30kg
					},
					ProductCodeDelivery: "3085", // Thuis bezorgen
					Customer: {
						CustomerNumber: orderId,
						CustomerCode: orderId,
					},
					Reference: orderId,
				},
			],
		};

		// Voeg direct verzonden items toe als aparte shipments
		shippingAddresses.forEach((shipping, index) => {
			if (shipping && shipping.postalCode) {
				shipmentData.Shipments.push({
					Addresses: [
						{
							AddressType: "01", // Thuis
							FirstName: shipping.firstName || "",
							Name: shipping.lastName || "",
							Street: shipping.streetAndNumber?.split(" ")[0] || "",
							HouseNr: shipping.streetAndNumber?.split(" ").slice(1).join(" ") || "",
							HouseNrExt: "",
							Zipcode: shipping.postalCode?.replace(/\s+/g, "") || "",
							City: shipping.city || "",
							Countrycode: (shipping.country || "NL").toUpperCase(),
						},
					],
					Dimension: {
						Weight: 100, // Minimaal gewicht voor direct verzonden items
					},
					ProductCodeDelivery: "3085", // Thuis bezorgen
					Customer: {
						CustomerNumber: `${orderId}-direct-${index}`,
						CustomerCode: `${orderId}-direct-${index}`,
					},
					Reference: `${orderId}-direct-${index}`,
				});
			}
		});

		// Maak shipment aan via PostNL API
		const shipmentResponse = await createPostNLShipment(shipmentData);
		
		if (!shipmentResponse || !shipmentResponse.ResponseShipments) {
			console.error("⚠️ Geen shipment response van PostNL");
			return null;
		}

		// Haal labels op voor elk shipment
		const labels = [];
		for (const responseShipment of shipmentResponse.ResponseShipments) {
			if (responseShipment.Labels && responseShipment.Labels.length > 0) {
				for (const label of responseShipment.Labels) {
					if (label.Label) {
						labels.push({
							barcode: label.Barcode || "",
							label: label.Label || "", // Base64 encoded label
							shipmentId: responseShipment.ShipmentId || "",
							reference: responseShipment.Reference || orderId,
						});
					}
				}
			}
		}

		console.log(`✅ PostNL labels gegenereerd voor ${orderId}: ${labels.length} label(s)`);
		return labels;
	} catch (e) {
		console.error(`❌ PostNL label generatie mislukt voor ${orderId}:`, e);
		return null;
	}
}

// Sla labels op in een Map voor later ophalen
const orderLabels = new Map(); // orderId -> labels array

// PostNL helper: verstuur labels via e-mail
async function sendPostNLLabelsViaEmail({ orderId, labels, sender }) {
	if (!labels || labels.length === 0) {
		console.warn(`⚠️ Geen labels om te versturen voor ${orderId}`);
		return;
	}

	try {
		// Maak HTML e-mail met labels als bijlagen
		const labelsHtml = labels.map((label, index) => {
			return `
				<div style="margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
					<h3 style="margin-top: 0;">Label ${index + 1}</h3>
					<p><strong>Barcode:</strong> ${label.barcode || "N/A"}</p>
					<p><strong>Shipment ID:</strong> ${label.shipmentId || "N/A"}</p>
					<p><strong>Reference:</strong> ${label.reference || orderId}</p>
					<img src="data:image/png;base64,${label.label}" alt="PostNL Label ${index + 1}" style="max-width: 100%; height: auto; border: 1px solid #ccc;" />
				</div>
			`;
		}).join("");

		const html = `
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="UTF-8">
				<title>PostNL Labels - Bestelling ${orderId}</title>
			</head>
			<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
				<div style="max-width: 800px; margin: 0 auto; padding: 20px;">
					<h1 style="color: #0066cc;">PostNL Barcodelabels</h1>
					<p><strong>Bestelling:</strong> ${orderId}</p>
					${sender ? `<p><strong>Afzender:</strong> ${sender.firstName} ${sender.lastName}</p>` : ""}
					<p><strong>Aantal labels:</strong> ${labels.length}</p>
					
					<div style="margin-top: 30px;">
						<h2>Labels:</h2>
						${labelsHtml}
					</div>
					
					<p style="margin-top: 30px; color: #666; font-size: 12px;">
						Deze labels zijn gegenereerd via de PostNL API. Print ze uit en plak ze op de pakketten.
					</p>
				</div>
			</body>
			</html>
		`;

		const text = `
PostNL Barcodelabels
Bestelling: ${orderId}
${sender ? `Afzender: ${sender.firstName} ${sender.lastName}` : ""}
Aantal labels: ${labels.length}

Labels:
${labels.map((label, index) => `
Label ${index + 1}:
- Barcode: ${label.barcode || "N/A"}
- Shipment ID: ${label.shipmentId || "N/A"}
- Reference: ${label.reference || orderId}
`).join("\n")}

Deze labels zijn gegenereerd via de PostNL API. Print ze uit en plak ze op de pakketten.
		`;

		// Verstuur naar bestellingen@momena.nl
		await sendEmailViaSendGrid({
			to: "bestellingen@momena.nl",
			subject: `PostNL Labels - Bestelling ${orderId}`,
			html,
			text,
		});

		console.log(`📧 PostNL labels verzonden via e-mail voor ${orderId}`);
	} catch (e) {
		console.error(`❌ E-mail verzending van labels mislukt voor ${orderId}:`, e);
		throw e;
	}
}

/* --------- Checkout ---------- */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const sender = req.body?.sender || null;
    const senderPrefs = req.body?.senderPrefs || {};
    const discount = Number(req.body?.discount || 0);
    const orderId = req.body?.orderId || `order_${Date.now()}`;

    const catalog = loadCatalog();
    const itemsTotal = calcTotal(items, catalog);
    const discountAmount = Number(discount || 0);
    const shippingCost = Number(req.body?.shippingCost || 0);
    const total = Math.max(0, itemsTotal - discountAmount + shippingCost);

    if (!total || total <= 0) {
      return res.status(400).json({ error: "Cart is empty or invalid" });
    }

    const stockError = validateStock(items, catalog);
    if (stockError) {
      return res.status(400).json({ error: stockError });
    }

    const description = `Order ${orderId} – ${items.length} items`;

    // Sla altijd de volledige metadata op voor gebruik in webhook/e-mails
    // Voeg ook gecomprimeerde metadata toe voor Mollie's 100 bytes limiet
    const mollieMeta = req.body?.mollieMeta;
    
    // Volledige metadata voor webhook en e-mails
    const fullMetadata = { 
      orderId, 
      items, 
      sender, 
      senderPrefs, 
      discount: discountAmount, 
      shippingCost 
    };
    
    // Metadata voor Mollie: voeg gecomprimeerde versie toe als extra veld
    const metadata = { ...fullMetadata };
    if (mollieMeta && typeof mollieMeta === 'string') {
      // Voeg gecomprimeerde metadata toe als extra veld voor Mollie's limiet
      metadata.mollieMeta = mollieMeta;
    }

    // Debug logging om te zien wat er wordt opgeslagen
    console.log(`📦 Metadata voor payment ${orderId}:`, {
      orderId,
      itemsCount: items.length,
      hasSender: !!sender,
      discount: discountAmount,
      shippingCost,
      hasMollieMeta: !!metadata.mollieMeta,
      metadataSize: JSON.stringify(metadata).length,
    });

    const payment = await mollie("/payments", "POST", {
      amount: { currency: "EUR", value: total.toFixed(2) },
      description,
      redirectUrl: `${FRONTEND_URL}/bedankt?orderId=${encodeURIComponent(
        orderId
      )}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      metadata: metadata,
    });
    
    // Debug logging om te zien wat Mollie heeft opgeslagen
    console.log(`📦 Payment aangemaakt voor ${orderId}, metadata in payment:`, payment.metadata);

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

      // Stuur orderbevestigings e-mails wanneer betaling succesvol is
      if (
        (status === "paid" || status === "authorized") &&
        !emailsSentOrders.has(orderId) &&
        payment.metadata
      ) {
        try {
          const metadata = payment.metadata;
          
          // Debug logging om te zien wat er in de metadata zit
          console.log(`🔍 Metadata voor ${orderId}:`, JSON.stringify(metadata, null, 2));
          
          const items = extractItemsFromMetadata(metadata);
          const sender = metadata.sender || null;
          const discount = Number(metadata.discount || 0);
          const shippingCost = Number(metadata.shippingCost || 0);
          const paymentAmount = Number(payment.amount?.value || 0);

          // Debug logging om te zien wat er wordt geëxtraheerd
          console.log(`🔍 Items geëxtraheerd:`, items.length, "items");
          console.log(`🔍 Sender:`, sender ? `${sender.firstName} ${sender.lastName}` : "geen sender");
          console.log(`🔍 Discount:`, discount);
          console.log(`🔍 Shipping cost:`, shippingCost);

          if (!items || items.length === 0) {
            console.error(`⚠️ Geen items gevonden in metadata voor ${orderId}`);
          }
          if (!sender) {
            console.error(`⚠️ Geen sender gevonden in metadata voor ${orderId}`);
          }

          await sendOrderConfirmationEmails({
            orderId,
            items,
            sender,
            total: paymentAmount,
            discount,
            shippingCost,
          });
          
          emailsSentOrders.add(orderId);
          console.log(`📧 Orderbevestigings e-mails verzonden voor ${orderId}`);

          // Genereer PostNL barcodelabels voor de bestelling
          try {
            // Verzamel alle direct verzonden adressen uit items
            const shippingAddresses = items
              .filter((item) => item.sendNow && item.shipping)
              .map((item) => item.shipping);

            const labels = await generatePostNLLabels({
              orderId,
              sender,
              items,
              shippingAddresses,
            });

            if (labels && labels.length > 0) {
              console.log(`✅ PostNL labels gegenereerd voor ${orderId}: ${labels.length} label(s)`);
              
              // Sla labels op voor later ophalen
              orderLabels.set(orderId, labels);
              
              // Verstuur labels via e-mail naar bestellingen@momena.nl
              try {
                await sendPostNLLabelsViaEmail({
                  orderId,
                  labels,
                  sender,
                });
              } catch (emailError) {
                console.error(`❌ E-mail verzending van labels mislukt voor ${orderId}:`, emailError);
                // E-mail fout mag label generatie niet blokkeren
              }
            } else {
              console.warn(`⚠️ Geen labels gegenereerd voor ${orderId}`);
            }
          } catch (labelError) {
            console.error(`❌ PostNL label generatie mislukt voor ${orderId}:`, labelError);
            // Label generatie fout mag e-mail verzending niet blokkeren
          }
        } catch (emailError) {
          console.error(`❌ Orderbevestigings e-mails mislukt voor ${orderId}:`, emailError);
          console.error(`❌ Error details:`, emailError.stack);
          // Voeg niet toe aan emailsSentOrders zodat het opnieuw kan worden geprobeerd
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

// Endpoint om PostNL labels op te halen
app.get("/api/postnl-labels", (req, res) => {
  const orderId = req.query.orderId;
  if (!orderId) {
    return res.status(400).json({ error: "orderId required" });
  }
  
  const labels = orderLabels.get(orderId);
  if (!labels || labels.length === 0) {
    return res.status(404).json({ error: "Geen labels gevonden voor deze bestelling" });
  }
  
  res.json({ orderId, labels });
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
