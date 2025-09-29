/**
 * Cart + Mollie Payments backend (robuste /api/products) + Email via Nodemailer
 */
try { require("dotenv").config(); } catch {}

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");
const fetch =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const app = express();
const PORT = process.env.PORT || 3000;

/* ------------ ENV ------------ */
const MOLLIE_API_KEY = process.env.MOLLIE_API_KEY;
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");

// E-mail env (LET OP: gebruik precies deze keys in Render/.env)
const SMTP_HOST   = process.env.SMTP_HOST;
const SMTP_PORT   = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";
const SMTP_USER   = process.env.SMTP_USER;
const SMTP_PASS   = process.env.SMTP_PASS;

// ontvanger & afzender
const ORDERS_TO   = process.env.ORDERS_TO; // bv. bestellingen@momena.nl
const ORDERS_FROM = process.env.ORDERS_FROM || (SMTP_USER || "no-reply@example.com");

if (!MOLLIE_API_KEY)  console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL)    console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL) console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");
if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !ORDERS_TO) {
  console.warn("⚠️ SMTP/Email env ontbreekt (SMTP_HOST, SMTP_USER, SMTP_PASS, ORDERS_TO). Emails worden niet verstuurd.");
}

/* ------------ Mail transporter ------------ */
let transporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE, // Strato: meestal false + poort 587
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

/* ------------ CORS & body parsing ------------ */
app.use(cors({ origin: FRONTEND_URL || "*" }));
app.use(express.json());
app.use("/api/mollie/webhook", express.urlencoded({ extended: false }));

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();
/** om dubbele mails te voorkomen als Mollie de webhook meerdere keren schiet */
const mailedOrderIds = new Set();

/* ------------ Products helpers ------------ */
const PRODUCTS_PATH = path.join(__dirname, "products.json");

function loadCatalog() {
  try {
    const raw = fs.readFileSync(PRODUCTS_PATH, "utf8");
    const json = JSON.parse(raw);
    const list = Array.isArray(json) ? json : json?.products || [];
    const normalized = list.map((p) => {
      const priceRaw = typeof p.price === "string" ? p.price.replace(",", ".") : p.price;
      const price = Number(priceRaw) || 0;
      return {
        id: String(p.id),
        name: String(p.name),
        price,
        image: p.image || undefined,
      };
    });
    return normalized;
  } catch (e) {
    console.error("Failed to load/parse products.json:", e.message);
    return [];
  }
}

function getProduct(id) {
  const catalog = loadCatalog();
  return catalog.find((p) => p.id === id);
}

function calcTotal(items) {
  let sum = 0;
  const catalog = loadCatalog();
  for (const it of items || []) {
    const p = catalog.find((x) => x.id === it.id);
    const qty = Math.max(0, Number(it.qty || 0));
    if (!p || qty <= 0) continue;
    sum += p.price * qty;
  }
  return Number(sum.toFixed(2));
}

function formatEUR(n) {
  try {
    return new Intl.NumberFormat("nl-NL", { style: "currency", currency: "EUR" }).format(n);
  } catch {
    return `€${Number(n).toFixed(2)}`;
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

/* ------------ Email helpers ------------ */
function renderAddressHtml(addr = {}) {
  const lines = [
    addr.firstName && addr.lastName ? `${escapeHtml(addr.firstName)} ${escapeHtml(addr.lastName)}` : null,
    addr.streetAndNumber ? escapeHtml(addr.streetAndNumber) : null,
    (addr.postalCode || addr.city) ? `${escapeHtml(addr.postalCode || "")} ${escapeHtml(addr.city || "")}`.trim() : null,
    addr.country ? escapeHtml(addr.country) : null,
  ].filter(Boolean);
  return lines.length ? `<div>${lines.join("<br/>")}</div>` : `<div><i>—</i></div>`;
}

function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function buildOrderEmailHtml({ orderId, status, items, payment }) {
  const catalog = loadCatalog();

  const rows = (items || []).map((it) => {
    const p = catalog.find((x) => x.id === it.id) || { name: it.id, price: 0 };
    const qty = Number(it.qty || 0);
    const lineTotal = (p.price || 0) * qty;

    const noteHtml = it.note
      ? `<div style="margin-top:6px;">
           <b>Bericht op kaart:</b><br/>
           <pre style="white-space:pre-wrap;font:inherit;border:1px solid #eee;border-radius:8px;padding:8px;background:#fafafa;">${escapeHtml(it.note)}</pre>
         </div>`
      : "";

    const shippingHtml = it.sendNow && it.shipping
      ? `<div style="margin-top:6px;"><b>Verzenden naar:</b>${renderAddressHtml(it.shipping)}</div>`
      : "";

    return `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top;">
          <div><b>${escapeHtml(p.name)}</b> <span style="opacity:.7;">(${escapeHtml(it.id)})</span></div>
          <div style="opacity:.8;">Stukprijs: ${formatEUR(p.price || 0)}</div>
          ${noteHtml}
          ${shippingHtml}
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;vertical-align:top;">${qty}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;vertical-align:top;">${formatEUR(lineTotal)}</td>
      </tr>
    `;
  }).join("");

  const total = calcTotal(items || []);
  const metaBlock = `
    <details style="margin-top:12px;">
      <summary style="cursor:pointer">Technische metadata (JSON)</summary>
      <pre style="white-space:pre-wrap;border:1px solid #eee;border-radius:8px;padding:8px;background:#fafafa;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;">${escapeHtml(JSON.stringify({ orderId, status, items, paymentId: payment?.id }, null, 2))}</pre>
    </details>
  `;

  return `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.45;color:#111;">
      <h2 style="margin:0 0 4px 0;">Nieuwe bestelling: ${escapeHtml(orderId)}</h2>
      <div style="opacity:.8;margin-bottom:12px;">Status: <b>${escapeHtml(status)}</b></div>

      <table cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;">
        <thead>
          <tr>
            <th align="left" style="text-align:left;padding:8px 12px;border-bottom:2px solid #333;">Product</th>
            <th align="right" style="text-align:right;padding:8px 12px;border-bottom:2px solid #333;">Aantal</th>
            <th align="right" style="text-align:right;padding:8px 12px;border-bottom:2px solid #333;">Totaal</th>
          </tr>
        </thead>
        <tbody>
          ${rows || ""}
        </tbody>
        <tfoot>
          <tr>
            <td></td>
            <td style="padding:10px 12px;text-align:right;"><b>Totaal</b></td>
            <td style="padding:10px 12px;text-align:right;"><b>${formatEUR(total)}</b></td>
          </tr>
        </tfoot>
      </table>

      ${metaBlock}
    </div>
  `;
}

async function sendOrderEmail({ orderId, status, items, payment }) {
  if (!transporter || !ORDERS_TO) {
    console.warn("✉️  Email overslagen (geen transporter/ORDERS_TO).");
    return;
  }
  const subject = `[Order] ${orderId} — ${status}`;
  const html = buildOrderEmailHtml({ orderId, status, items, payment });

  const info = await transporter.sendMail({
    from: ORDERS_FROM,
    to: ORDERS_TO,
    subject,
    html,
  });
  console.log(`✉️  Order mail verzonden (${orderId}) -> ${ORDERS_TO}. MessageId=${info.messageId}`);
}

/* ------------ Routes ------------ */
app.get("/", (_req, res) => res.send("Cart backend up ✅"));

/** Products: altijd gevuld/gestandaardiseerd */
app.get("/api/products", (_req, res) => {
  const catalog = loadCatalog();
  res.set("Cache-Control", "no-store");
  res.json({ products: catalog });
});

/** Maak betaling aan op basis van cart */
app.post("/api/create-payment-from-cart", async (req, res) => {
  try {
    // items [{ id, qty, note?, sendNow?, shipping?{firstName,lastName,streetAndNumber,postalCode,city,country} }]
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
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
      // ⬇️ Stuur alles mee in metadata, dit komt terug in de webhook:
      metadata: { orderId, items },
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
    theOrderId = payment?.metadata?.orderId;
    const orderId = payment?.metadata?.orderId;
    const items = Array.isArray(payment?.metadata?.items) ? payment.metadata.items : [];

    if (orderId) {
      statusesByOrderId.set(orderId, status);
      paymentIdByOrderId.set(orderId, paymentId);
      console.log(`🔔 ${orderId} -> ${status}`);
    }

    // Alleen mailen als betaald/authorized en nog niet gemaild
    if (orderId && (status === "paid" || status === "authorized") && !mailedOrderIds.has(orderId)) {
      try {
        await sendOrderEmail({ orderId, status, items, payment });
        mailedOrderIds.add(orderId);
      } catch (mailErr) {
        console.error("❌ Kon order-mail niet sturen:", mailErr);
      }
    }

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

/** Test e-mail (om SMTP snel te checken) */
app.get("/api/test-email", async (_req, res) => {
  try {
    await sendOrderEmail({
      orderId: "TEST-" + Date.now(),
      status: "paid",
      items: [
        {
          id: "test-product",
          qty: 1,
          note: "Dit is een testbericht.",
          sendNow: true,
          shipping: {
            firstName: "Test",
            lastName: "Klant",
            streetAndNumber: "Dorpsstraat 1",
            postalCode: "1234 AB",
            city: "Amsterdam",
            country: "Nederland",
          },
        },
      ],
      payment: { id: "dummy" },
    });
    res.json({ ok: true, message: "Testmail verzonden (check ORDERS_TO inbox)" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server on :${PORT}`);
  console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
  console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
  if (transporter) console.log("✉️  Email transporter klaar (Nodemailer)");
  else console.log("✉️  Email transporter NIET actief (check .env SMTP settings)");
});
