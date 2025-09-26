/**
 * Cart + Mollie Payments backend
 */
try { require('dotenv').config(); } catch {}

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const fetch = global.fetch || ((...args) => import('node-fetch').then(({default: f}) => f(...args)));

const app = express();
const PORT = process.env.PORT || 3000;
const MOLLIE_API_KEY = process.env.MOLLIE_API_KEY;
const FRONTEND_URL = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');

if (!MOLLIE_API_KEY) console.warn('⚠️ Missing MOLLIE_API_KEY');
if (!FRONTEND_URL) console.warn('⚠️ Missing FRONTEND_URL');
if (!PUBLIC_BASE_URL) console.warn('⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)');

// CORS: allow your Framer site
app.use(cors({
  origin: FRONTEND_URL || true
}));
app.use(express.json());
app.use('/api/mollie/webhook', express.urlencoded({ extended: false }));

// In-memory status store
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();

// Load products
const PRODUCTS_PATH = path.join(__dirname, 'products.json');
let CATALOG = [];
try {
  CATALOG = JSON.parse(fs.readFileSync(PRODUCTS_PATH, 'utf8'));
} catch (e) {
  console.error('Failed to load products.json', e);
  CATALOG = [];
}

function getProduct(id) {
  return CATALOG.find(p => p.id === id);
}

function calcTotal(items) {
  // items: [{id, qty}]
  let sum = 0;
  for (const it of items || []) {
    const p = getProduct(it.id);
    const qty = Math.max(0, Number(it.qty || 0));
    if (!p || qty <= 0) continue;
    sum += p.price * qty;
  }
  return Number(sum.toFixed(2));
}

async function mollie(path, method='GET', body) {
  const res = await fetch(`https://api.mollie.com/v2${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${MOLLIE_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) throw new Error(`Mollie ${res.status}: ${await res.text()}`);
  return res.json();
}

// Health
app.get('/', (_req, res) => res.send('Cart backend up ✅'));

// List products
app.get('/api/products', (_req, res) => {
  res.json({ products: CATALOG });
});

// Create payment from cart
app.post('/api/create-payment-from-cart', async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const orderId = req.body?.orderId || `order_${Date.now()}`;

    // Validate and price on server
    const total = calcTotal(items);
    if (!total || total <= 0) {
      return res.status(400).json({ error: 'Cart is empty or invalid' });
    }

    const description = `Order ${orderId} – ${items.length} items`;

    const payment = await mollie('/payments', 'POST', {
      amount: { currency: 'EUR', value: total.toFixed(2) },
      description,
      redirectUrl: `${FRONTEND_URL}/bedankt?orderId=${encodeURIComponent(orderId)}`,
      webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
      metadata: { orderId, items }
    });

    // store mapping
    if (payment?.metadata?.orderId && payment?.id) {
      paymentIdByOrderId.set(payment.metadata.orderId, payment.id);
    }

    const checkoutUrl = payment?._links?.checkout?.href;
    if (!checkoutUrl) throw new Error('No checkout URL from Mollie');

    res.json({ checkoutUrl, paymentId: payment.id, orderId, total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create payment' });
  }
});

// Webhook
app.post('/api/mollie/webhook', async (req, res) => {
  const paymentId = req.body?.id;
  if (!paymentId) return res.status(200).send('OK');
  try {
    const payment = await mollie(`/payments/${paymentId}`, 'GET');
    const status = payment?.status || 'unknown';
    const orderId = payment?.metadata?.orderId;
    if (orderId) {
      statusesByOrderId.set(orderId, status);
      paymentIdByOrderId.set(orderId, paymentId);
      console.log(`🔔 ${orderId} -> ${status}`);
    }
    res.status(200).send('OK');
  } catch (e) {
    console.error('Webhook error:', e);
    res.status(500).send('Webhook error');
  }
});

// Order/status helpers
app.get('/api/order-status', (req, res) => {
  const orderId = req.query.orderId;
  if (!orderId) return res.status(400).json({ error: 'orderId required' });
  const status = statusesByOrderId.get(orderId) || 'unknown';
  const paymentId = paymentIdByOrderId.get(orderId) || null;
  res.json({ orderId, status, paymentId });
});

app.get('/api/payment-status', async (req, res) => {
  const paymentId = req.query.paymentId;
  if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
  try {
    const payment = await mollie(`/payments/${paymentId}`, 'GET');
    res.json({ paymentId, status: payment?.status || 'unknown' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch status' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server on :${PORT}`);
  console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
  console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
});
