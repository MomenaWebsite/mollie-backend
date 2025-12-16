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
const sgMail = require("@sendgrid/mail");
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
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const EMAIL_SENDER_NAME = process.env.EMAIL_SENDER_NAME || "Momena";
const EMAIL_FROM_ADDRESS = process.env.EMAIL_FROM || "noreply@momena.nl";
const EMAIL_FROM = `${EMAIL_SENDER_NAME} <${EMAIL_FROM_ADDRESS}>`;
const ORDER_EMAIL_TO = process.env.ORDER_EMAIL_TO || "bestellingen@momena.nl";

if (!MOLLIE_API_KEY) console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL) console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL)
  console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");
if (JWT_SECRET === "change-me-in-env")
  console.warn("⚠️ Set a strong JWT_SECRET in env");
if (!SENDGRID_API_KEY) console.warn("⚠️ Missing SENDGRID_API_KEY");

// Configureer SendGrid
if (SENDGRID_API_KEY) {
  sgMail.setApiKey(SENDGRID_API_KEY);
}

/* ------------ CORS & body parsing ------------ */
function parseOrigins(input) {
  const s = String(input || "").trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}
const ALLOWED_ORIGINS = parseOrigins(FRONTEND_URL);

// Voeg ook expliciet momena.nl URLs toe
const ALLOWED_ORIGINS_LIST = [
  ...ALLOWED_ORIGINS,
  "https://momena.nl",
  "https://www.momena.nl",
].filter((url, index, self) => self.indexOf(url) === index); // Remove duplicates

// Functie om te checken of een origin is toegestaan (inclusief Framer development URLs)
function isOriginAllowed(origin) {
  if (!origin) return true; // Allow requests without an origin (e.g., same-origin or direct server calls)
  
  // Exacte match
  if (ALLOWED_ORIGINS_LIST.includes(origin)) {
    return true;
  }
  
  // Framer Canvas URLs toestaan (alle *.framercanvas.com subdomeinen)
  if (origin.match(/^https:\/\/[a-z0-9-]+\.framercanvas\.com$/)) {
    return true;
  }
  
  // Framer Screenshot URLs toestaan (alle *.framer.invalid subdomeinen)
  if (origin.match(/^https:\/\/[a-z0-9-]+\.framer\.invalid$/)) {
    return true;
  }
  
  // Framer Website URLs toestaan (alle *.framer.website subdomeinen)
  if (origin.match(/^https:\/\/[a-z0-9-]+\.framer\.website$/)) {
    return true;
  }
  
  return false;
}

console.log("🌐 Allowed CORS origins:", ALLOWED_ORIGINS_LIST);
console.log("🌐 Framer development URLs (framercanvas.com, framer.invalid, framer.website) are also allowed");

app.use(
  cors({
    origin: (origin, cb) => {
      if (isOriginAllowed(origin)) {
        return cb(null, true);
      }
      console.error(`❌ CORS blocked for origin: ${origin}`);
      console.log("   Allowed origins:", ALLOWED_ORIGINS_LIST);
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

// Update voorraad direct in products.json
function updateStockInProducts(productId, newStock) {
  try {
    const state = readCatalogState();
    const products = state.list || [];
    
    const product = products.find((p) => String(p.id) === String(productId));
    if (!product) {
      return false;
    }
    
    const stockValue = Math.max(0, Math.floor(Number(newStock) || 0));
    product.stock = stockValue;
    
    return writeProductsFile(products);
  } catch (e) {
    console.error("❌ Kon voorraad niet bijwerken:", e.message);
    return false;
  }
}

function readCatalogState() {
  try {
    // Check of products.json bestaat
    if (!fs.existsSync(PRODUCTS_PATH)) {
      console.warn("⚠️ products.json niet gevonden, maak een lege array aan");
      // Maak een leeg bestand aan als het niet bestaat
      writeProductsFile([]);
      return { data: [], list: [], type: "array" };
    }
    
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
  // Schrijf products.json (wordt gebruikt voor producten en voorraad)
  return writeProductsFile(state.list || []);
}

// Schrijf products.json (alleen voor admin interface)
// Op Render: Bestand wordt bijgewerkt, maar blijft behouden tussen deploys
function writeProductsFile(products) {
  try {
    if (!Array.isArray(products)) {
      throw new Error("Products must be an array");
    }
    const jsonContent = JSON.stringify(products, null, 2);
    fs.writeFileSync(PRODUCTS_PATH, jsonContent, "utf8");
    console.log(`💾 products.json bijgewerkt met ${products.length} producten`);
    return true;
  } catch (e) {
    console.error("❌ Kon products.json niet schrijven:", e.message);
    return false;
  }
}

function normalizeProduct(p) {
  if (!p) {
    return { id: "", name: "", price: 0, image: undefined, stock: 0 };
  }
  const priceRaw =
    typeof p.price === "string" ? p.price.replace(",", ".") : p.price;
  const price = Number(priceRaw) || 0;
  
  // Lees voorraad direct uit products.json
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
  return state.list.map((p) => normalizeProduct(p));
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

  const catalog = loadCatalog();
  if (!Array.isArray(catalog) || catalog.length === 0) return false;

  const state = readCatalogState();
  const products = state.list || [];
  let changed = false;

  for (const item of items) {
    const id = String(item?.id || "");
    const qty = Math.max(0, Number(item?.qty || 0));
    if (!id || qty <= 0) continue;

    const product = products.find((p) => String(p.id) === id);
    if (!product) continue;

    // Update voorraad direct in products array
    const current = Number(product.stock ?? 0);
    const next = Math.max(0, current - qty);

    if (next !== current) {
      product.stock = next;
      changed = true;
    }
  }

  if (changed) {
    try {
      writeProductsFile(products); // Schrijf direct naar products.json
      console.log("✅ Voorraad bijgewerkt in products.json");
    } catch (e) {
      console.error("❌ Voorraad opslaan mislukt:", e);
      return false;
    }
  }

  return changed;
}

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();
const stockAdjustedOrders = new Set();
const emailsSent = new Set(); // Voorkom dubbele emails
// Sla volledige order data op om metadata klein te houden
const orderDataByOrderId = new Map();

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
    
    // Verstuur email met reset link
    await sendPasswordResetEmail(email, resetLink);

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


/* --------- Email Functions ---------- */
function formatEUR(n) {
  return new Intl.NumberFormat("nl-NL", {
    style: "currency",
    currency: "EUR",
  }).format(n);
}

// Converteer http URLs naar https voor email veiligheid
function ensureHttps(url) {
  if (!url) return null;
  if (typeof url !== "string") return url;
  // Als het al https is, return zoals het is
  if (url.startsWith("https://")) return url;
  // Converteer http naar https
  if (url.startsWith("http://")) {
    return url.replace("http://", "https://");
  }
  // Als het een relatief pad is, voeg https:// toe (aanname dat het van dezelfde domain komt)
  if (url.startsWith("//")) {
    return "https:" + url;
  }
  // Als het geen protocol heeft, voeg https:// toe
  if (!url.startsWith("http")) {
    // Als het een absoluut pad is (begint met /), voeg de domain toe
    if (url.startsWith("/")) {
      return `https://www.momena.nl${url}`;
    }
    // Anders, voeg https:// toe
    return `https://${url}`;
  }
  return url;
}

function generateOrderEmailHTML(orderData) {
  const {
    orderId,
    items,
    sender,
    discount,
    shippingCost,
    giftWrapCost,
    subTotal: subTotalFromData,
    subtotal: subtotalFromData,
    total,
  } = orderData;

  const catalog = loadCatalog();
  
  // Enrich items met product informatie
  const enrichedItems = items.map((item) => {
    const product = catalog.find((p) => String(p.id) === String(item.id));
    const price = Number(product?.price) || Number(item.price) || 0;
    const qty = Number(item.qty) || 0;
    const lineTotal = price * qty;
    return {
      ...item,
      name: product?.name || String(item.id || "Unknown"),
      price: price,
      image: product?.image || null,
      qty: qty,
      lineTotal: lineTotal,
    };
  });

  // Bereken subtotaal altijd opnieuw op basis van de items (voorkom NaN)
  const calculatedSubTotal = enrichedItems.reduce((sum, item) => {
    const lineTotal = Number(item.lineTotal) || 0;
    return sum + lineTotal;
  }, 0);
  
  // Gebruik berekend subtotaal, tenzij we een geldig subtotaal hebben uit de data
  const subTotal = (Number.isFinite(subTotalFromData) && subTotalFromData > 0) 
    ? Number(subTotalFromData) 
    : (Number.isFinite(subtotalFromData) && subtotalFromData > 0)
      ? Number(subtotalFromData)
      : calculatedSubTotal;

  const itemsHTML = enrichedItems
    .map((item) => {
      const safeImageUrl = ensureHttps(item.image);
      const imageHTML = safeImageUrl
        ? `<img src="${safeImageUrl}" alt="${item.name}" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px;" />`
        : '<div style="width: 80px; height: 80px; background: #f5f5f5; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #999; font-size: 12px;">Geen foto</div>';
      
      const sendNowHTML = item.sendNow
        ? `<div style="margin-top: 8px; padding: 8px; background: #e8f5e9; border-radius: 4px; font-size: 12px; color: #2e7d32;">
            <strong>Direct verzonden naar:</strong><br/>
            ${item.shipping?.firstName || ""} ${item.shipping?.lastName || ""}<br/>
            ${item.shipping?.streetAndNumber || ""}<br/>
            ${item.shipping?.postalCode || ""} ${item.shipping?.city || ""}<br/>
            ${item.shipping?.country || ""}<br/>
            ${item.shipping?.deliveryDate ? `Aankomst: ${item.shipping.deliveryDate}` : ""}
          </div>`
        : "";

      const noteHTML = item.note
        ? `<div style="margin-top: 8px; padding: 8px; background: #fff3e0; border-radius: 4px; font-size: 12px; color: #e65100;">
            <strong>Bericht:</strong> ${item.note}
          </div>`
        : "";

      const attachedCandlesHTML = item.attachedCandles && item.attachedCandles.length > 0
        ? `<div style="margin-top: 8px; padding: 8px; background: #f3e5f5; border-radius: 4px; font-size: 12px; color: #7b1fa2;">
            <strong>Meegestuurd:</strong> ${item.attachedCandles.map(c => `${c.qty} x ${c.id}`).join(", ")}
          </div>`
        : "";

      return `
        <tr>
          <td style="padding: 16px; border-bottom: 1px solid #eee;">
            <div style="display: flex; gap: 16px;">
              ${imageHTML}
              <div style="flex: 1;">
                <div style="font-weight: 600; margin-bottom: 8px;">${item.name}</div>
                <div style="font-size: 14px; color: #666;">${item.qty} x ${formatEUR(item.price)}</div>
                ${sendNowHTML}
                ${noteHTML}
                ${attachedCandlesHTML}
              </div>
              <div style="text-align: right; font-weight: 600;">${formatEUR(item.lineTotal)}</div>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  return `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px;">
        <div style="background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
          <h1 style="color: #333; margin-top: 0;">Bestelbevestiging</h1>
          
          <div style="margin-bottom: 24px;">
            <p><strong>Ordernummer:</strong> ${orderId}</p>
            <p><strong>Datum:</strong> ${new Date().toLocaleString("nl-NL")}</p>
          </div>

          <div style="margin-bottom: 24px; padding: 16px; background: #f5f5f5; border-radius: 8px;">
            <h2 style="margin-top: 0; font-size: 18px;">Afzender gegevens</h2>
            <p>
              ${sender?.firstName || ""} ${sender?.lastName || ""}<br/>
              ${sender?.streetAndNumber || ""}<br/>
              ${sender?.postalCode || ""} ${sender?.city || ""}<br/>
              ${sender?.country || ""}<br/>
              <br/>
              <strong>E-mail:</strong> ${sender?.email || ""}<br/>
              <strong>Telefoon:</strong> ${sender?.phone || ""}
            </p>
          </div>

          <div style="margin-bottom: 24px;">
            <h2 style="margin-top: 0; font-size: 18px;">Bestelde producten</h2>
            <table style="width: 100%; border-collapse: collapse;">
              ${itemsHTML}
            </table>
          </div>

          <div style="margin-bottom: 24px; padding: 16px; background: #f5f5f5; border-radius: 8px;">
            <table style="width: 100%;">
              <tr>
                <td style="padding: 8px 0;">Subtotaal:</td>
                <td style="text-align: right; padding: 8px 0;">${formatEUR(subTotal)}</td>
              </tr>
              ${discount > 0 ? `
              <tr>
                <td style="padding: 8px 0; color: #0a7f2e;">Korting:</td>
                <td style="text-align: right; padding: 8px 0; color: #0a7f2e;">- ${formatEUR(discount)}</td>
              </tr>
              ` : ""}
              ${shippingCost > 0 ? `
              <tr>
                <td style="padding: 8px 0;">Verzendkosten:</td>
                <td style="text-align: right; padding: 8px 0;">${formatEUR(shippingCost)}</td>
              </tr>
              ` : ""}
              ${giftWrapCost > 0 ? `
              <tr>
                <td style="padding: 8px 0;">Cadeau inpakken:</td>
                <td style="text-align: right; padding: 8px 0;">${formatEUR(giftWrapCost)}</td>
              </tr>
              ` : ""}
              <tr style="border-top: 2px solid #333;">
                <td style="padding: 8px 0; font-weight: 700; font-size: 18px;">Totaal:</td>
                <td style="text-align: right; padding: 8px 0; font-weight: 700; font-size: 18px;">${formatEUR(total)}</td>
              </tr>
            </table>
          </div>

          <p style="margin-top: 24px; padding-top: 24px; border-top: 1px solid #eee; font-size: 14px; color: #666;">
            Bedankt voor je bestelling! We verwerken deze zo snel mogelijk.
          </p>
        </div>
      </body>
    </html>
  `;
}

function generateOrderEmailText(orderData) {
  const {
    orderId,
    items,
    sender,
    discount,
    shippingCost,
    giftWrapCost,
    subTotal: subTotalFromData,
    subtotal: subtotalFromData,
    total,
  } = orderData;

  const catalog = loadCatalog();
  
  // Enrich items met product informatie
  const enrichedItems = items.map((item) => {
    const product = catalog.find((p) => String(p.id) === String(item.id));
    const price = Number(product?.price) || Number(item.price) || 0;
    const qty = Number(item.qty) || 0;
    const lineTotal = price * qty;
    return {
      ...item,
      name: product?.name || String(item.id || "Unknown"),
      price: price,
      qty: qty,
      lineTotal: lineTotal,
    };
  });

  // Bereken subtotaal altijd opnieuw op basis van de items (voorkom NaN)
  const calculatedSubTotal = enrichedItems.reduce((sum, item) => {
    const lineTotal = Number.isFinite(item.lineTotal) ? Number(item.lineTotal) : 0;
    if (!Number.isFinite(lineTotal)) {
      console.warn(`Invalid lineTotal for item ${item.id}:`, item.lineTotal);
      return sum;
    }
    return sum + lineTotal;
  }, 0);
  
  // Gebruik berekend subtotaal, tenzij we een geldig subtotaal hebben uit de data
  const subTotal = (Number.isFinite(subTotalFromData) && subTotalFromData > 0) 
    ? Number(subTotalFromData) 
    : (Number.isFinite(subtotalFromData) && subtotalFromData > 0)
      ? Number(subtotalFromData)
      : (Number.isFinite(calculatedSubTotal) ? calculatedSubTotal : 0);

  const itemsText = enrichedItems
    .map((item) => {
      const sendNowText = item.sendNow
        ? `\n  Direct verzonden naar:\n  ${item.shipping?.firstName || ""} ${item.shipping?.lastName || ""}\n  ${item.shipping?.streetAndNumber || ""}\n  ${item.shipping?.postalCode || ""} ${item.shipping?.city || ""}\n  ${item.shipping?.country || ""}\n  ${item.shipping?.deliveryDate ? `Aankomst: ${item.shipping.deliveryDate}` : ""}`
        : "";
      const noteText = item.note ? `\n  Bericht: ${item.note}` : "";
      const attachedCandlesText = item.attachedCandles && item.attachedCandles.length > 0
        ? `\n  Meegestuurd: ${item.attachedCandles.map(c => `${c.qty} x ${c.id}`).join(", ")}`
        : "";
      return `- ${item.name} (${item.qty} x ${formatEUR(item.price)}) = ${formatEUR(item.lineTotal)}${sendNowText}${noteText}${attachedCandlesText}`;
    })
    .join("\n\n");

  return `
BESTELBEVESTIGING

Ordernummer: ${orderId}
Datum: ${new Date().toLocaleString("nl-NL")}

AFZENDER GEGEVENS:
${sender?.firstName || ""} ${sender?.lastName || ""}
${sender?.streetAndNumber || ""}
${sender?.postalCode || ""} ${sender?.city || ""}
${sender?.country || ""}

E-mail: ${sender?.email || ""}
Telefoon: ${sender?.phone || ""}

BESTELDE PRODUCTEN:
${itemsText}

KOSTEN OVERZICHT:
Subtotaal: ${formatEUR(subTotal)}
${discount > 0 ? `Korting: -${formatEUR(discount)}\n` : ""}${shippingCost > 0 ? `Verzendkosten: ${formatEUR(shippingCost)}\n` : ""}${giftWrapCost > 0 ? `Cadeau inpakken: ${formatEUR(giftWrapCost)}\n` : ""}Totaal: ${formatEUR(total)}

Bedankt voor je bestelling! We verwerken deze zo snel mogelijk.
  `.trim();
}

async function sendPasswordResetEmail(email, resetLink) {
  if (!SENDGRID_API_KEY) {
    console.warn("⚠️ SENDGRID_API_KEY niet ingesteld, email niet verzonden");
    console.log(`📧 Reset Link (niet verzonden): ${resetLink}`);
    return;
  }

  try {
    const htmlContent = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h1 style="color: #333; margin-top: 0;">Wachtwoord opnieuw instellen</h1>
            
            <p>Je hebt aangevraagd om je wachtwoord opnieuw in te stellen voor je account.</p>
            
            <p>Klik op de onderstaande link om je wachtwoord opnieuw in te stellen:</p>
            
            <div style="margin: 24px 0; text-align: center;">
              <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background: #333; color: #fff; text-decoration: none; border-radius: 4px; font-weight: 600;">
                Wachtwoord opnieuw instellen
              </a>
            </div>
            
            <p style="font-size: 14px; color: #666;">
              Of kopieer en plak deze link in je browser:<br/>
              <a href="${resetLink}" style="color: #333; word-break: break-all;">${resetLink}</a>
            </p>
            
            <p style="font-size: 14px; color: #666; margin-top: 24px;">
              Deze link is 1 uur geldig. Als je deze aanvraag niet hebt gedaan, negeer deze email dan.
            </p>
          </div>
        </body>
      </html>
    `;

    const textContent = `
WACHTWOORD OPNIEUW INSTELLEN

Je hebt aangevraagd om je wachtwoord opnieuw in te stellen voor je account.

Klik op de onderstaande link om je wachtwoord opnieuw in te stellen:

${resetLink}

Deze link is 1 uur geldig. Als je deze aanvraag niet hebt gedaan, negeer deze email dan.
    `.trim();

    await sgMail.send({
      to: email,
      from: EMAIL_FROM,
      subject: "Wachtwoord opnieuw instellen",
      text: textContent,
      html: htmlContent,
    });
    
    console.log(`✅ Wachtwoord reset email verzonden naar: ${email}`);
  } catch (error) {
    console.error("❌ Fout bij verzenden wachtwoord reset email:", error);
    if (error.response) {
      console.error("SendGrid error details:", error.response.body);
    }
    // Log de link als fallback
    console.log(`📧 Reset Link (fallback): ${resetLink}`);
  }
}

async function sendOrderConfirmationEmail(orderData) {
  if (!SENDGRID_API_KEY) {
    console.warn("⚠️ SENDGRID_API_KEY niet ingesteld, email niet verzonden");
    return;
  }

  try {
    const htmlContent = generateOrderEmailHTML(orderData);
    const textContent = generateOrderEmailText(orderData);
    const customerEmail = orderData.sender?.email;

    // Email naar klant
    if (customerEmail) {
      await sgMail.send({
        to: customerEmail,
        from: EMAIL_FROM,
        subject: `Bestelbevestiging ${orderData.orderId}`,
        text: textContent,
        html: htmlContent,
      });
      console.log(`✅ Email verzonden naar klant: ${customerEmail}`);
    }

    // Email naar bestellingen@momena.nl
    await sgMail.send({
      to: ORDER_EMAIL_TO,
      from: EMAIL_FROM,
      subject: `Nieuwe bestelling ${orderData.orderId}`,
      text: textContent,
      html: htmlContent,
    });
    console.log(`✅ Email verzonden naar ${ORDER_EMAIL_TO}`);

  } catch (error) {
    console.error("❌ Fout bij verzenden email:", error);
    if (error.response) {
      console.error("SendGrid error details:", error.response.body);
    }
  }
}

/* --------- Checkout ---------- */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const sender = req.body?.sender || null;
    const senderPrefs = req.body?.senderPrefs || {};
    const orderId = req.body?.orderId || `order_${Date.now()}`;
    
    // Haal discount, shippingCost en giftWrapCost uit de request body
    const discount = Number(req.body?.discount || 0);
    const promoCode = req.body?.promoCode || null;
    const shippingCost = Number(req.body?.shippingCost || 0);
    const giftWrapCost = Number(req.body?.giftWrapCost || 0);

    // Valideer kortingscode als deze is opgegeven (frontend berekent de korting al)
    if (promoCode) {
      const code = promoCode.trim().toUpperCase();
      if (code !== "NIEUWEMOMENA" && code !== "WOUTGRATISVERZENDING" && code !== "GRATISVERZENDINGWOUT") {
        return res.status(400).json({ error: "Ongeldige kortingscode" });
      }
    }

    const catalog = loadCatalog();
    const subtotal = calcTotal(items, catalog);
    
    // Bereken het totaal inclusief discount (al inclusief bulk + kortingscode korting), verzendkosten en inpakkosten
    const total = Math.max(0, subtotal - discount + shippingCost + giftWrapCost);

    if (!subtotal || subtotal <= 0) {
      return res.status(400).json({ error: "Cart is empty or invalid" });
    }

    const stockError = validateStock(items, catalog);
    if (stockError) {
      return res.status(400).json({ error: stockError });
    }

    const description = `Order ${orderId} – ${items.length} items`;

    // Sla volledige order data op in-memory (om metadata klein te houden)
    orderDataByOrderId.set(orderId, {
      items,
      sender,
      senderPrefs,
      discount, // Totale korting (bulk + kortingscode, al berekend in frontend)
      promoCode: promoCode,
      shippingCost,
      giftWrapCost,
      subtotal,
      total,
    });

    // Stuur alleen orderId in Mollie metadata (binnen 1024 bytes limiet)
    const payment = await mollie("/payments", "POST", {
      amount: { currency: "EUR", value: total.toFixed(2) },
      description,
      redirectUrl: `https://www.momena.nl/bedankt?orderId=${encodeURIComponent(
        orderId
      )}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      metadata: { orderId },
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
        // Haal items uit in-memory storage in plaats van metadata
        const orderData = orderDataByOrderId.get(orderId);
        const items = orderData?.items || extractItemsFromMetadata(payment.metadata);
        const changed = updateStockForItems(items);
        if (changed) {
          console.log(`📦 Voorraad bijgewerkt voor ${orderId}`);
        }
        stockAdjustedOrders.add(orderId);
      }

      // Verstuur email wanneer betaling is betaald en email nog niet is verzonden
      if (status === "paid" && !emailsSent.has(orderId)) {
        const orderData = orderDataByOrderId.get(orderId);
        if (orderData) {
          await sendOrderConfirmationEmail({
            ...orderData,
            orderId,
          });
          emailsSent.add(orderId);
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

app.get("/api/order-details", async (req, res) => {
  const orderId = req.query.orderId;
  if (!orderId) {
    return res.status(400).json({ error: "orderId required" });
  }

  try {
    // Probeer paymentId op te halen uit de map
    let paymentId = paymentIdByOrderId.get(orderId);
    
    // Als er geen paymentId is, probeer de status endpoint te gebruiken
    if (!paymentId) {
      const status = statusesByOrderId.get(orderId);
      // Als er geen status is, kunnen we de payment niet vinden
      if (!status) {
        return res.status(404).json({ error: "Order not found" });
      }
    }

    // Als we nog steeds geen paymentId hebben, proberen we alle payments te doorzoeken
    // Dit is niet ideaal maar kan nodig zijn als de map leeg is
    if (!paymentId) {
      try {
        const payments = await mollie("/payments", "GET", {
          limit: 250, // Mollie's maximum
        });
        const payment = payments._embedded?.payments?.find(
          (p) => p.metadata?.orderId === orderId
        );
        if (payment) {
          paymentId = payment.id;
          paymentIdByOrderId.set(orderId, paymentId);
        }
      } catch (e) {
        console.error("Error searching payments:", e);
      }
    }

    if (!paymentId) {
      return res.status(404).json({ error: "Payment not found for this order" });
    }

    // Haal payment op van Mollie
    const payment = await mollie(`/payments/${paymentId}`, "GET");
    if (!payment) {
      return res.status(404).json({ error: "Payment not found" });
    }

    // Haal order data uit in-memory storage (fallback naar metadata voor oude orders)
    const orderData = orderDataByOrderId.get(orderId);
    let items, sender, senderPrefs, discount, shippingCost, giftWrapCost, subTotal, total;
    
    if (orderData) {
      // Nieuwe orders: gebruik in-memory data
      items = orderData.items || [];
      sender = orderData.sender || null;
      senderPrefs = orderData.senderPrefs || {};
      discount = Number(orderData.discount || 0);
      shippingCost = Number(orderData.shippingCost || 0);
      giftWrapCost = Number(orderData.giftWrapCost || 0);
      subTotal = Number(orderData.subtotal || 0);
      total = Number(orderData.total || 0);
    } else {
      // Oude orders: fallback naar metadata (voor backwards compatibility)
      const metadata = payment.metadata || {};
      items = extractItemsFromMetadata(metadata);
      sender = metadata.sender || null;
      senderPrefs = metadata.senderPrefs || {};
      discount = Number(metadata.discount || 0);
      shippingCost = Number(metadata.shippingCost || 0);
      giftWrapCost = Number(metadata.giftWrapCost || 0);
      subTotal = 0; // Wordt later berekend
      total = 0; // Wordt later berekend
    }

    // Enrich items met product informatie
    const catalog = loadCatalog();
    const enrichedItems = items.map((item) => {
      const product = catalog.find((p) => String(p.id) === String(item.id));
      return {
        id: String(item.id || ""),
        name: product?.name || String(item.id || "Unknown"),
        price: product?.price || Number(item.price || 0),
        image: product?.image || null,
        qty: Number(item.qty || 0),
        lineTotal: (product?.price || Number(item.price || 0)) * Number(item.qty || 0),
        sendNow: Boolean(item.sendNow || false),
        note: item.note || undefined,
        shipping: item.shipping || undefined,
        attachedCandles: item.attachedCandles || undefined,
      };
    });

    // Gebruik opgeslagen subtotaal/totaal als beschikbaar, anders bereken
    const finalSubTotal = subTotal > 0 ? subTotal : enrichedItems.reduce((sum, item) => sum + item.lineTotal, 0);
    const finalTotal = total > 0 ? total : Math.max(0, finalSubTotal - discount + shippingCost + giftWrapCost);

    // Haal status op
    const status = statusesByOrderId.get(orderId) || payment.status || "unknown";

    res.json({
      orderId,
      paymentId,
      status,
      sender,
      discount,
      shippingCost,
      giftWrapCost,
      subTotal: finalSubTotal,
      total: finalTotal,
      items: enrichedItems,
    });
  } catch (e) {
    console.error("Error fetching order details:", e);
    res.status(500).json({ error: "Failed to fetch order details" });
  }
});

// =======================
// ADMIN API ENDPOINTS
// =======================

// Test endpoint om te controleren of admin endpoints werken
app.get("/api/admin/test", (_req, res) => {
  res.json({ 
    success: true, 
    message: "Admin API is actief",
    timestamp: new Date().toISOString()
  });
});

// Haal alle producten op met voorraad (direct uit products.json)
app.get("/api/admin/products", async (req, res) => {
  try {
    const catalog = loadCatalog();
    res.json({ products: catalog });
  } catch (e) {
    console.error("Error fetching admin products:", e);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Voeg nieuw product toe
app.post("/api/admin/products", async (req, res) => {
  try {
    const { id, name, price, image, stock } = req.body;
    
    if (!id || !name || price === undefined) {
      return res.status(400).json({ error: "id, name en price zijn verplicht" });
    }
    
    const state = readCatalogState();
    const products = state.list || [];
    
    // Check of product al bestaat
    if (products.find((p) => String(p.id) === String(id))) {
      return res.status(400).json({ error: "Product met dit ID bestaat al" });
    }
    
    // Voeg product toe
    const newProduct = {
      id: String(id),
      name: String(name),
      price: Number(price) || 0,
      image: image || undefined,
    };
    
    products.push(newProduct);
    
    // Voeg stock toe aan product
    if (stock !== undefined && stock !== null) {
      newProduct.stock = Math.max(0, Math.floor(Number(stock) || 0));
    } else {
      newProduct.stock = 0;
    }
    
    // Schrijf naar products.json
    if (!writeProductsFile(products)) {
      return res.status(500).json({ error: "Kon product niet toevoegen" });
    }
    
    res.json({ success: true, product: newProduct });
  } catch (e) {
    console.error("Error adding product:", e);
    res.status(500).json({ error: "Failed to add product" });
  }
});

// Bewerk product
app.put("/api/admin/products/:id", async (req, res) => {
  try {
    const productId = req.params.id;
    const { name, price, image } = req.body;
    
    const state = readCatalogState();
    const products = state.list || [];
    
    const productIndex = products.findIndex((p) => String(p.id) === String(productId));
    if (productIndex === -1) {
      return res.status(404).json({ error: "Product niet gevonden" });
    }
    
    // Update product
    if (name !== undefined) products[productIndex].name = String(name);
    if (price !== undefined) products[productIndex].price = Number(price) || 0;
    if (image !== undefined) products[productIndex].image = image || undefined;
    
    // Schrijf naar products.json
    if (!writeProductsFile(products)) {
      return res.status(500).json({ error: "Kon product niet bijwerken" });
    }
    
    res.json({ success: true, product: products[productIndex] });
  } catch (e) {
    console.error("Error updating product:", e);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// Verwijder product
app.delete("/api/admin/products/:id", async (req, res) => {
  try {
    const productId = req.params.id;
    
    const state = readCatalogState();
    const products = state.list || [];
    
    const productIndex = products.findIndex((p) => String(p.id) === String(productId));
    if (productIndex === -1) {
      return res.status(404).json({ error: "Product niet gevonden" });
    }
    
    // Verwijder product
    products.splice(productIndex, 1);
    
    // Schrijf naar products.json
    if (!writeProductsFile(products)) {
      return res.status(500).json({ error: "Kon product niet verwijderen" });
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error("Error deleting product:", e);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// Update voorraad (direct in products.json)
app.put("/api/admin/stock/:id", async (req, res) => {
  try {
    const productId = req.params.id;
    const { stock } = req.body;
    
    if (stock === undefined || stock === null) {
      return res.status(400).json({ error: "stock is verplicht" });
    }
    
    const stockAmount = Math.max(0, Math.floor(Number(stock) || 0));
    
    if (!updateStockInProducts(productId, stockAmount)) {
      return res.status(500).json({ error: "Kon voorraad niet bijwerken" });
    }
    
    res.json({ success: true, stock: stockAmount });
  } catch (e) {
    console.error("Error updating stock:", e);
    res.status(500).json({ error: "Failed to update stock" });
  }
});

// Products.json is nu de enige bron voor producten en voorraad
// Op Render: Zorg dat products.json op Persistent Disk staat of in de repo
console.log("✅ Producten en voorraad worden beheerd via products.json");
console.log(`📁 Locatie: ${PRODUCTS_PATH}`);

// Initialiseer products.json als het niet bestaat
if (!fs.existsSync(PRODUCTS_PATH)) {
  console.log("📦 Initialiseren lege products.json...");
  writeProductsFile([]);
}

app.listen(PORT, () => {
  console.log(`✅ Server on :${PORT}`);
  console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
  console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
});
