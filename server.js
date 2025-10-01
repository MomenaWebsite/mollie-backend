/**
 * Cart + Mollie Payments backend (robuste /api/products) — ZONDER e-mail
 */
try { require("dotenv").config(); } catch {}

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const fetch =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const app = express();
const PORT = process.env.PORT || 3000;

/* ------------ ENV ------------ */
const MOLLIE_API_KEY  = process.env.MOLLIE_API_KEY;
const FRONTEND_URL    = (process.env.FRONTEND_URL    || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");

if (!MOLLIE_API_KEY)  console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL)    console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL) console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");

/* ------------ CORS & body parsing ------------ */
app.use(cors({ origin: FRONTEND_URL || "*" }));
app.use(express.json());
app.use("/api/mollie/webhook", express.urlencoded({ extended: false }));

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();

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

/* ------------ Routes ------------ */
app.get("/", (_req, res) => res.send("Cart backend up ✅"));

/** Products: altijd gevuld/gestandaardiseerd */
app.get("/api/products", (_req, res) => {
  const catalog = loadCatalog();
  res.set("Cache-Control", "no-store");
  res.json({ products: catalog });
});

/** Maak betaling aan op basis van cart + sender info */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    // body structuur (vanuit frontend):
    // {
    //   items: [{ id, qty, note?, sendNow?, shipping?{firstName,lastName,streetAndNumber,postalCode,city,country} }],
    //   sender: {
    //     firstName, lastName, street, number, postalCode, city, country, phone, email, streetAndNumber?
    //   },
    //   senderPrefs: { tosAccepted: boolean, newsletter: boolean },
    //   orderId?: string
    // }
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const rawSender = req.body?.sender || {};
    const senderPrefs = req.body?.senderPrefs || {};
    const orderId = req.body?.orderId || `order_${Date.now()}`;

    const total = calcTotal(items);
    if (!total || total <= 0) {
      return res.status(400).json({ error: "Cart is empty or invalid" });
    }

    // Normaliseer sender en voeg streetAndNumber toe als die los is aangeleverd
    const sender = {
      firstName: String(rawSender.firstName || ""),
      lastName: String(rawSender.lastName || ""),
      street: String(rawSender.street || ""),
      number: String(rawSender.number || ""),
      postalCode: String(rawSender.postalCode || ""),
      city: String(rawSender.city || ""),
      country: String(rawSender.country || ""),
      phone: String(rawSender.phone || ""),
      email: String(rawSender.email || ""),
      streetAndNumber: String(
        rawSender.streetAndNumber || `${rawSender.street || ""} ${rawSender.number || ""}`.trim()
      ),
    };

    // Zachte validatie (loggen i.p.v. hard blocken — frontend houdt al tegen)
    const missingSenderFields = [];
    for (const key of ["firstName","lastName","street","number","postalCode","city","country","phone","email"]) {
      if (!sender[key]?.toString().trim()) missingSenderFields.push(key);
    }
    if (missingSenderFields.length) {
      console.warn(`ℹ️ Sender mist velden: ${missingSenderFields.join(", ")}`);
      // We blokkeren hier NIET; frontend valideert al, dit is vooral logging.
    }

    const description = `Order ${orderId} – ${items.length} items`;

    const payment = await mollie("/payments", "POST", {
      amount: { currency: "EUR", value: total.toFixed(2) },
      description,
      redirectUrl: `${FRONTEND_URL}/bedankt?orderId=${encodeURIComponent(orderId)}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      // ⬇️ Alles meegeven in metadata, zodat je het in Mollie terugziet
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

/** Mollie webhook */
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

    // (Geen e-mail meer)
    res.status(200).send("OK");
  } catch (e) {
    console.error("Webhook error:", e);
    res.status(500).send("Webhook error");
  }
});

/** Order/status helpers */
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
