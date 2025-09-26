/**
 * Simple Mollie backend (Node + Express)
 * - POST /api/create-payment -> creates a Mollie payment and returns checkoutUrl + paymentId
 * - POST /api/mollie/webhook  -> Mollie calls this with form-encoded body: id=<paymentId>
 * - GET  /api/order-status?orderId=... -> returns last known status for that order (from webhook)
 * - GET  /api/payment-status?paymentId=... -> fetches live status from Mollie
 *
 * Read README.md for deployment steps.
 */
require('dotenv').config?.();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const MOLLIE_API_KEY = process.env.MOLLIE_API_KEY; // test_xxx or live_xxx
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

if (!MOLLIE_API_KEY) {
  console.warn('⚠️  Missing MOLLIE_API_KEY. Set it in your environment (test_... for testing).');
}

app.use(cors());
app.use(express.json());

// Mollie webhook posts x-www-form-urlencoded by default
app.use('/api/mollie/webhook', express.urlencoded({ extended: false }));

// In-memory store (MVP). For production use a database.
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();

async function mollie(path, method = 'GET', body) {
  const res = await fetch(`https://api.mollie.com/v2${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${MOLLIE_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Mollie error ${res.status}: ${txt}`);
  }
  return res.json();
}

app.get('/', (_req, res) => {
  res.send('Mollie backend up ✅');
});

// Create a payment and return checkout URL
app.post('/api/create-payment', async (req, res) => {
  try {
    const { amount, description, orderId, metadata, method } = req.body || {};

    if (!amount) return res.status(400).json({ error: 'amount is required' });
    const value = Number(amount).toFixed(2);

    const safeOrderId = orderId || `order_${Date.now()}`;

    const payment = await mollie('/payments', 'POST', {
      amount: { currency: 'EUR', value },
      description: description || `Order ${safeOrderId}`,
      redirectUrl: `${FRONTEND_URL}/bedankt?orderId=${encodeURIComponent(safeOrderId)}`,
      webhookUrl: `${process.env.PUBLIC_BASE_URL || ''}/api/mollie/webhook`.replace(/\/$/, ''),
      metadata: { orderId: safeOrderId, ...(metadata || {}) },
      ...(method ? { method } : {}), // optional: e.g. 'ideal'
    });

    // keep quick mapping in memory
    if (payment?.metadata?.orderId && payment?.id) {
      paymentIdByOrderId.set(payment.metadata.orderId, payment.id);
    }

    const checkoutUrl = payment?._links?.checkout?.href;
    if (!checkoutUrl) throw new Error('No checkout URL in Mollie response');

    res.json({ checkoutUrl, paymentId: payment.id, orderId: safeOrderId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create payment' });
  }
});

// Webhook: Mollie posts id=<paymentId>
app.post('/api/mollie/webhook', async (req, res) => {
  const paymentId = req.body?.id;
  if (!paymentId) {
    console.warn('Webhook called without payment id');
    return res.status(200).send('OK');
  }

  try {
    const payment = await mollie(`/payments/${paymentId}`, 'GET');
    const status = payment?.status || 'unknown';
    const orderId = payment?.metadata?.orderId;

    if (orderId) {
      statusesByOrderId.set(orderId, status);
      paymentIdByOrderId.set(orderId, paymentId);
      console.log(`🔔 Webhook: order ${orderId} -> ${status}`);
    } else {
      console.log(`🔔 Webhook: payment ${paymentId} -> ${status}`);
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(500).send('Webhook error');
  }
});

// Query by orderId (uses last webhook result)
app.get('/api/order-status', (req, res) => {
  const orderId = req.query.orderId;
  if (!orderId) return res.status(400).json({ error: 'orderId is required' });

  const status = statusesByOrderId.get(orderId) || 'unknown';
  const paymentId = paymentIdByOrderId.get(orderId) || null;
  res.json({ orderId, status, paymentId });
});

// Query live status by paymentId
app.get('/api/payment-status', async (req, res) => {
  const paymentId = req.query.paymentId;
  if (!paymentId) return res.status(400).json({ error: 'paymentId is required' });

  try {
    const payment = await mollie(`/payments/${paymentId}`, 'GET');
    res.json({ paymentId, status: payment?.status || 'unknown' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch status' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`Frontend redirect base: ${FRONTEND_URL}`);
  if (!process.env.PUBLIC_BASE_URL) {
    console.log('⚠️  Set PUBLIC_BASE_URL to your deployed backend URL so webhookUrl is valid.');
  }
});
