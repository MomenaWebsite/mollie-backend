# Mollie Checkout Backend (Express)

This is a minimal backend that works with the **Mollie Payments API**. It creates a payment, handles the webhook, and lets your Framer site check the status.

## 1) Prereqs
- Mollie account with **Test API key** (find it in Mollie Dashboard → Developers → API Keys).
- A public host (Render, Railway, Vercel, etc.).

## 2) Configure
Create `.env` from the example:
```
cp .env.example .env
```

Fill:
- `MOLLIE_API_KEY=test_xxx...`  (use test key first)
- `FRONTEND_URL=https://your-framer-site.framer.website`  (your Framer domain)
- `PUBLIC_BASE_URL=https://your-backend.onrender.com`     (the public URL of this backend; used in webhookUrl)

## 3) Run locally
```
npm install
npm start
```
Server runs at `http://localhost:3000`

> For webhooks in local dev, expose your server with a tunnel (e.g. ngrok).

## 4) Deploy (example: Render)
1. Push this folder to a new GitHub repo.
2. On Render → **New +** → **Web Service** → connect your repo.
3. **Build command**: `npm install`
4. **Start command**: `node server.js`
5. Add **Environment Variables**:
   - `MOLLIE_API_KEY` = your test key
   - `FRONTEND_URL` = your Framer site, e.g. `https://yourproject.framer.website`
   - `PUBLIC_BASE_URL` = the Render URL after first deploy (update and redeploy once you have it)
6. Copy the Render URL and put it into Framer code (see framer/README).

## Endpoints
- `POST /api/create-payment` → body: `{ amount, description, orderId?, metadata?, method? }`
  - Returns: `{ checkoutUrl, paymentId, orderId }`
- `POST /api/mollie/webhook` → Mollie calls this with `id=<paymentId>` (form-encoded)
- `GET  /api/order-status?orderId=...`
- `GET  /api/payment-status?paymentId=...`

## Notes
- This kit uses an **in-memory store** for order status (MVP). For production, save to a database.
- Always verify the status from Mollie (via webhook or `/payments/{id}`) before fulfilling an order.
