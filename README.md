# Cart Backend (Mollie Payments API)

Features:
- Serves a simple product catalog (`GET /api/products`)
- Calculates totals on the server from a cart payload
- Creates a Mollie payment (`POST /api/create-payment-from-cart`)
- Webhook + status endpoints

## Configure (.env)
```
MOLLIE_API_KEY=test_xxx
FRONTEND_URL=https://momenatest.framer.website
PUBLIC_BASE_URL=https://<your-backend>.onrender.com
PORT=3000
```
Deploy the same way as before (Render).

## Endpoints
- `GET /api/products` → returns sample products
- `POST /api/create-payment-from-cart`
  Body:
  ```json
  {
    "items": [{"id":"card-birthday","qty":2},{"id":"candle-cocktail","qty":1}],
    "orderId": "optional_order_123"
  }
  ```
  Returns: `{ checkoutUrl, paymentId, orderId, total }`

- `POST /api/mollie/webhook` (called by Mollie)
- `GET /api/order-status?orderId=...`
- `GET /api/payment-status?paymentId=...`
