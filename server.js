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
// ----------------------------------------------------
const nodemailer = require("nodemailer"); // <-- 1. NODEMAILER IMPORTEREN
// ----------------------------------------------------
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

if (!MOLLIE_API_KEY) console.warn("⚠️ Missing MOLLIE_API_KEY");
if (!FRONTEND_URL) console.warn("⚠️ Missing FRONTEND_URL");
if (!PUBLIC_BASE_URL)
	console.warn("⚠️ Missing PUBLIC_BASE_URL (webhookUrl may be invalid)");
if (JWT_SECRET === "change-me-in-env")
	console.warn("⚠️ Set a strong JWT_SECRET in env");

/* ------------ NODEMAILER SETUP (Poort 587) ------------ */

const transporter = nodemailer.createTransport({
	host: process.env.EMAIL_HOST,
	port: 587, // Geforceerd op 587
	secure: false, // BELANGRIJK: 'false' voor poort 587 (gebruikt STARTTLS)
	auth: {
		user: process.env.EMAIL_USER, // Typisch 'apikey' voor SendGrid
		pass: process.env.EMAIL_PASS,
	},
});

/* ------------ NODEMAILER FUNCTIES ------------ */

const SENDER_EMAIL = "info@momena.nl"; // Hardcoded, geverifieerd e-mailadres
// NIEUW: Intern e-mailadres voor orderbevestigingen
const INTERNAL_ORDER_EMAIL = "bestellingen@momena.nl"; 

// Functie om de reset-e-mail te versturen
async function sendResetEmail(userEmail, resetLink) {
	const mailOptions = {
		from: `"${process.env.EMAIL_SENDER_NAME || 'Wachtwoord Service'}" <${SENDER_EMAIL}>`,
		to: userEmail,
		subject: 'Wachtwoord Resetten voor uw account',
		html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: auto;">
                <p>Hallo,</p>
                <p>U ontvangt deze e-mail omdat u een verzoek heeft ingediend om uw wachtwoord te resetten.</p>
                <p>Klik op de onderstaande knop om uw wachtwoord te wijzigen. Deze link is slechts één uur geldig.</p>
                <div style="margin: 20px 0;">
                    <a href="${resetLink}" 
                        style="display: inline-block; padding: 10px 20px; color: #ffffff; background-color: #007bff; border-radius: 5px; text-decoration: none; font-weight: bold;"
                    >
                        Wachtwoord Resetten
                    </a>
                </div>
                <p>Als u dit niet heeft aangevraagd, kunt u deze e-mail negeren. Uw wachtwoord zal dan ongewijzigd blijven.</p>
            </div>
        `,
	};

	try {
		await transporter.sendMail(mailOptions);
		console.log(`[EMAIL] Reset e-mail succesvol voor ${userEmail} klaargezet.`);
	} catch (error) {
		console.error(`[EMAIL FOUT] Kon e-mail naar ${userEmail} niet verzenden:`, error);
	}
}

// NIEUW: Functie om de orderbevestiging te versturen
async function sendOrderConfirmationEmail(payment) {
	const catalog = loadCatalog();
	const totalPaid = Number(payment?.amount?.value) || 0;
	const items = extractItemsFromMetadata(payment.metadata);
	const customer = payment.metadata.sender;
	const discount = Number(payment.metadata.discount) || 0;
	const subTotal = totalPaid + discount; // Subtotaal is betaald + korting

	if (!customer || !customer.email) {
		console.error("[EMAIL FOUT] Geen e-mailadres van klant in metadata.");
		// Blijf versturen naar intern adres, zelfs als klant e-mail mist (cruciale aanpassing)
	}

	// Bouw de HTML voor de productenlijst
	const itemRows = items.map(item => {
		const product = catalog.find(p => p.id === item.id);
		const itemPrice = product?.price || 0;
		const totalLine = (item.qty * itemPrice).toFixed(2).replace('.', ',');
		const name = product?.name || item.id;

		// Specifieke verzendinformatie voor individuele items
		let shippingInfo = '';
		if (item.sendNow) {
			// Individueel verstuurde items
			shippingInfo = `
                <p style="margin: 4px 0 0 0; font-size: 12px; color: #555;">
                    Verstuurd naar: ${item.shipping.firstName} ${item.shipping.lastName}
                </p>
                <p style="margin: 2px 0 0 0; font-size: 12px; color: #555;">
                    Adres: ${item.shipping.streetAndNumber}, ${item.shipping.postalCode} ${item.shipping.city}
                </p>
                <p style="margin: 2px 0 0 0; font-size: 12px; color: #555;">
                    Gewenste aankomst: ${item.shipping.deliveryDate}
                </p>
            `;
			if (item.note) {
				shippingInfo += `<p style="margin: 2px 0 0 0; font-size: 12px; color: #555;">Bericht: ${item.note}</p>`;
			}
		} else if (item.qty > 0 && !item.sendNow) {
			// Bulk items (gaan naar afzender/klant)
			shippingInfo = `<p style="margin: 4px 0 0 0; font-size: 12px; color: #555;">Wordt in bulk naar uw adres verstuurd.</p>`;
		}

		return `
            <tr>
                <td style="padding: 8px 0; border-bottom: 1px solid #eee;">
                    ${item.qty} x ${name}
                    ${shippingInfo}
                </td>
                <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;">
                    &euro; ${totalLine}
                </td>
            </tr>
        `;
	}).join('');

	// Totaal sectie
	const discountRow = discount > 0 ? `
        <tr>
            <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #0a7f2e;">Korting</td>
            <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #0a7f2e;">- &euro; ${discount.toFixed(2).replace('.', ',')}</td>
        </tr>
    ` : '';
    
    // Bepaal de ontvangerslijst
    const recipients = [INTERNAL_ORDER_EMAIL];
    if (customer && customer.email) {
        recipients.unshift(customer.email); // Plaats klant bovenaan als hoofdontvanger
    }

	const mailOptions = {
		from: `"${process.env.EMAIL_SENDER_NAME || 'Momena'}" <${SENDER_EMAIL}>`,
		// AANPASSING: Stuur naar KLANT EN INTERN adres
		to: recipients.join(', '), 
		subject: `Bestelbevestiging #${payment.metadata.orderId} (Klant: ${customer?.firstName || 'Onbekend'} ${customer?.lastName || 'Onbekend'})`,
		html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: auto; border: 1px solid #eee; padding: 20px;">
                <h2 style="color: #333;">Bedankt voor uw bestelling!</h2>
                <p>Uw bestelling met nummer <strong>${payment.metadata.orderId}</strong> is succesvol betaald. Hieronder vindt u een overzicht:</p>

                <table width="100%" cellpadding="0" cellspacing="0" style="margin-top: 20px; border-collapse: collapse;">
                    <thead>
                        <tr>
                            <th style="text-align: left; padding-bottom: 10px; border-bottom: 2px solid #333;">Product</th>
                            <th style="text-align: right; padding-bottom: 10px; border-bottom: 2px solid #333;">Totaal</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${itemRows}
                    </tbody>
                    <tfoot>
                        <tr>
                            <td style="padding: 8px 0; text-align: right;">Subtotaal</td>
                            <td style="padding: 8px 0; text-align: right;">&euro; ${subTotal.toFixed(2).replace('.', ',')}</td>
                        </tr>
                        ${discountRow}
                        <tr>
                            <td style="padding: 10px 0; border-top: 2px solid #333; font-weight: bold; font-size: 18px; text-align: right;">Totaal Betaald</td>
                            <td style="padding: 10px 0; border-top: 2px solid #333; font-weight: bold; font-size: 18px; text-align: right;">&euro; ${totalPaid.toFixed(2).replace('.', ',')}</td>
                        </tr>
                    </tfoot>
                </table>
                
                <h3 style="color: #333; margin-top: 30px;">Uw Gegevens (Afzender)</h3>
                <p style="margin: 5px 0; font-size: 14px;"><strong>Naam:</strong> ${customer?.firstName || ''} ${customer?.lastName || ''}</p>
                <p style="margin: 5px 0; font-size: 14px;"><strong>Adres:</strong> ${customer?.streetAndNumber || ''}, ${customer?.postalCode || ''} ${customer?.city || ''}, ${customer?.country || ''}</p>
                <p style="margin: 5px 0; font-size: 14px;"><strong>E-mail:</strong> ${customer?.email || ''}</p>
                <p style="margin: 5px 0; font-size: 14px;"><strong>Telefoon:</strong> ${customer?.phone || ''}</p>

                <p style="margin-top: 30px;">Wij houden u op de hoogte! Bedankt voor uw aankoop.</p>
                <p style="font-size: 12px; color: #888;">&copy; ${new Date().getFullYear()} Momena. Alle rechten voorbehouden.</p>
            </div>
        `,
	};

	try {
		await transporter.sendMail(mailOptions);
		console.log(`[EMAIL] Orderbevestiging succesvol verstuurd naar ${recipients.join(', ')}.`);
	} catch (error) {
		console.error(`[EMAIL FOUT] Kon orderbevestiging niet verzenden:`, error);
	}
}

/* ------------ CORS & body parsing (AANGEPAST VOOR FRAMER PREVIEW) ------------ */
function parseOrigins(input) {
	const s = String(input || "").trim();
	if (!s) return [];
	return s.split(",").map((x) => x.trim()).filter(Boolean);
}

// Lijst van toegestane origins, inclusief de Framer preview URL
const BASE_ORIGINS = [
	(process.env.FRONTEND_URL || "").replace(/\/$/, ""),
	(process.env.PUBLIC_BASE_URL || "").replace(/\/$/, ""),
	// Toevoeging om Framer preview fout te fixen
	'https://screenshot.framer.invalid',
	// Voor lokale ontwikkeling:
	'http://localhost:3000',
	'http://localhost:4000',
].filter(Boolean);

const ALLOWED_ORIGINS = parseOrigins(BASE_ORIGINS.join(','));


app.use(
	cors({
		origin: (origin, cb) => {
			if (!origin) return cb(null, true);
			// Controleer of de origin is toegestaan
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
		name: String(p.name || "").replace(/-/g, " "),
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

/* ------------ In-memory order status ------------ */
const statusesByOrderId = new Map();
const paymentIdByOrderId = new Map();
const stockAdjustedOrders = new Set();

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
		
		await sendResetEmail(email, resetLink);

		res.json({
			ok: true,
			message: "Een reset link is naar uw e-mailadres verzonden. Controleer ook uw spam-folder.",
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
		const discount = Number(req.body?.discount) || 0;

		const catalog = loadCatalog();
		const subTotal = calcTotal(items, catalog);
		const finalTotal = Math.max(0, subTotal - discount);

		if (!finalTotal || finalTotal <= 0) {
			return res.status(400).json({ error: "Cart is empty or invalid" });
		}

		const stockError = validateStock(items, catalog);
		if (stockError) {
			return res.status(400).json({ error: stockError });
		}

		const description = `Order ${orderId} – ${items.length} items`;

		const payment = await mollie("/payments", "POST", {
			amount: { currency: "EUR", value: finalTotal.toFixed(2) },
			description,
			// Redirect naar Framer 'bedankt' pagina met orderId in de URL
			redirectUrl: `https://momenatest.framer.website/bedankt?orderId=${encodeURIComponent(orderId)}`,
			webhookUrl: `${PUBLIC_BASE_URL}/api/mollie/webhook`,
			metadata: { orderId, items, sender, senderPrefs, discount: discount },
		});

		if (payment?.metadata?.orderId && payment?.id) {
			paymentIdByOrderId.set(payment.metadata.orderId, payment.id);
		}

		const checkoutUrl = payment?._links?.checkout?.href;
		if (!checkoutUrl) throw new Error("No checkout URL from Mollie");

		res.json({ checkoutUrl, paymentId: payment.id, orderId, total: finalTotal });
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
				
				// STUUR ORDERBEVESTIGING E-MAIL naar klant EN intern adres
				await sendOrderConfirmationEmail(payment); 
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

/* --------- Order details (for Thank You page) ---------- */
app.get("/api/order-details", async (req, res) => {
    try {
        const orderId = String(req.query.orderId || "").trim()
        if (!orderId) return res.status(400).json({ error: "orderId required" })

        // Vind paymentId uit geheugen; indien niet aanwezig: fout teruggeven
        const paymentId = paymentIdByOrderId.get(orderId)
        if (!paymentId) {
            return res.status(404).json({ error: "Order niet gevonden" })
        }

        // Haal payment op bij Mollie (bevat metadata → items, sender, discount)
        const payment = await mollie(`/payments/${paymentId}`, "GET")
        const status = payment?.status || "unknown"
        const metadata = payment?.metadata || {}
        const items = extractItemsFromMetadata(metadata)
        const sender = metadata?.sender || null
        const discount = Number(metadata?.discount) || 0

        // Verrijk met catalogus voor prijs en naam
        const catalog = loadCatalog()
        const enrichedItems = (items || []).map((it) => {
            const p = catalog.find((x) => String(x.id) === String(it.id))
            const price = Number(p?.price || 0)
            const name = p ? p.name : String(it.id)
            const image = p?.image || null
            const qty = Math.max(0, Number(it.qty || 0))
            const lineTotal = Number((price * qty).toFixed(2))
            return {
                id: it.id,
                name,
                price,
                image,
                qty,
                lineTotal,
                sendNow: !!it.sendNow,
                note: it.note || undefined,
                shipping: it.shipping || undefined,
                attachedCandles: it.attachedCandles || undefined,
            }
        })

        const subTotal = enrichedItems.reduce((sum, it) => sum + it.lineTotal, 0)
        const total = Math.max(0, Number((subTotal - discount).toFixed(2)))

        res.json({
            orderId,
            paymentId,
            status,
            sender,
            discount,
            subTotal,
            total,
            items: enrichedItems,
        })
    } catch (e) {
        console.error("Order details error:", e)
        res.status(500).json({ error: "Failed to load order details" })
    }
})

app.listen(PORT, () => {
	console.log(`✅ Server on :${PORT}`);
	console.log(`FRONTEND_URL: ${FRONTEND_URL}`);
	console.log(`PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}`);
});
