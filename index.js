const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const NodeCache = require('node-cache');
const winston = require('winston');
const morgan = require('morgan');
const { computeDelivery, computeSubtotal, validateZoneTiers, DEFAULT_ZONES } = require('./deliveryEngine');
const appCache = new NodeCache({ stdTTL: 30, checkperiod: 10 }); // 30s TTL — short enough that admin changes appear quickly
require('dotenv').config();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
} else {
  logger.warn('STRIPE_SECRET_KEY is missing in environment variables.');
}
// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: String(reason) });
});

const port = process.env.PORT || 5000;

// CORS
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'https://redleaf-bd.vercel.app',
    'https://redleafbd-8a215.web.app',
    'https://redleafbd-8a215.firebaseapp.com',
    'https://redleaf-bd-frontend-i83q.vercel.app',
    'https://redleaf-bd.com',
    'https://www.redleaf-bd.com',
    process.env.CLIENT_ADDRESS,
    process.env.DEV_CLIENT,
  ].filter(Boolean),
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
};

app.set('trust proxy', 1); // Correct IP detection behind Vercel / reverse proxy
app.use(cors(corsOptions));
app.use(express.json({ limit: '100kb' }));
app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' } }));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// ─── Tiered Rate Limiting ─────────────────────────────────────────────────────
// Public product browsing — generous limit (cached anyway, near-zero DB cost)
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
});
// Auth endpoints — strict (prevents brute-force login attacks)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many auth attempts, please wait.' },
});
// Protected API (orders, cart, payments) — moderate
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
});

app.use('/products', publicLimiter);   // public: 2000 req / 15 min
app.use('/jwt', authLimiter);     // auth:   20 req / 15 min (brute-force guard)
app.use('/login', authLimiter);
app.use(apiLimiter);                   // everything else: 500 req / 15 min
app.use(compression({ level: 6, threshold: 1024 }));


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.rxvwb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ─── Cold-start ready gate ────────────────────────────────────────────────────
// run() registers routes asynchronously. On Vercel cold starts, requests can
// arrive before run() finishes → 404. This gate makes every request wait until
// run() has completed route registration.
let _resolveReady;
const dbReadyPromise = new Promise((resolve) => { _resolveReady = resolve; });
let dbReady = false;

app.use(async (req, res, next) => {
  // Let the root health-check through immediately
  if (req.path === '/') return next();
  // JWT and user-registration are already outside run(), let them through
  if (req.path === '/jwt' || (req.path === '/users' && req.method === 'POST')) return next();
  if (!dbReady) {
    try { await dbReadyPromise; } catch { return res.status(503).send({ message: 'Server is starting, please retry.' }); }
  }
  next();
});

// ─── JWT ──────────────────────────────────────────────────────────────────────
app.post('/jwt', async (req, res) => {
  try {
    const user = req.body;
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '2h' });
    res.send({ token });
  } catch (error) {
    res.status(500).send({ message: 'Failed to generate token', error: error.message });
  }
});

// ─── User registration (must be outside run() for Vercel cold starts) ─────────
app.post('/users', async (req, res) => {
  try {
    // FIXED: use correct DB name "Redleaf-BD"
    const userCollection = client.db('Redleaf-BD').collection('users');
    const user = req.body;
    const query = { email: user.email };
    const existingUser = await userCollection.findOne(query);
    if (existingUser) {
      return res.send({ message: 'User already exists', insertedId: existingUser._id });
    }
    const userData = {
      email: user.email,
      name: user.name || user.displayName || 'User',
      photoURL: user.photoURL || null,
      role: 'user',
      createdAt: new Date(),
    };
    const result = await userCollection.insertOne(userData);
    res.send({ message: 'User created successfully', insertedId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: 'Failed to create user', error: error.message });
  }
});

// ─── Main run function ────────────────────────────────────────────────────────
async function run() {
  try {
    const db = client.db('Redleaf-BD');
    const userCollection = db.collection('users');
    const contactCollection = db.collection('contactCollection');
    const profileCollection = db.collection('profiles');
    const productCollection = db.collection('products');
    const cartCollection = db.collection('carts');
    const orderCollection = db.collection('orders');
    const paymentCollection = db.collection('payments');
    const blogCollection = db.collection('blogs');
    const settingsCollection = db.collection('settings');
    const featuredCollection = db.collection('featuredProducts');

    // Create indexes for O(log n) query performance
    await Promise.all([
      // Products
      productCollection.createIndex({ category: 1 }),
      productCollection.createIndex({ price: 1 }),
      productCollection.createIndex({ sold: -1 }),
      productCollection.createIndex({ createdAt: -1 }),
      // Orders
      orderCollection.createIndex({ email: 1 }),
      orderCollection.createIndex({ status: 1 }),
      orderCollection.createIndex({ orderedAt: -1 }),
      // Payments
      paymentCollection.createIndex({ createdAt: -1 }),
      paymentCollection.createIndex({ transactionId: 1 }, { sparse: true }),
      paymentCollection.createIndex({ orderId: 1 }),
      // Users / Profiles / Carts
      userCollection.createIndex({ email: 1 }, { unique: true }),
      cartCollection.createIndex({ email: 1 }),
      featuredCollection.createIndex({ productId: 1 }, { unique: true }),
      featuredCollection.createIndex({ addedAt: -1 }),
    ]).catch(err => logger.warn('Index warning:', { message: err.message }));
    logger.info('✅ DB indexes ensured.');

    // ── Auth Middleware ───────────────────────────────────────────────────────
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ message: 'unauthorized access' });
        req.decoded = decoded;
        next();
      });
    };

    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await userCollection.findOne({ email });
      if (user?.role !== 'admin') {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    };

    // ═══════════════════════════════════════════════════════════════════════════
    //  USER MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════
    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { search, role, page = 1, limit = 10, sort = 'name', order = 'asc' } = req.query;
        let query = {};
        if (search) {
          query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ];
        }
        if (role && role !== 'all') query.role = role;

        const sortObj = { [sort]: order === 'desc' ? -1 : 1 };
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [users, total] = await Promise.all([
          userCollection.find(query).sort(sortObj).skip(skip).limit(parseInt(limit)).toArray(),
          userCollection.countDocuments(query),
        ]);
        res.send({ users, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch users' });
      }
    });

    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const user = await userCollection.findOne({ email });
        res.send({ admin: user?.role === 'admin' });
      } catch (error) {
        res.status(500).send({ message: 'Failed to check admin status' });
      }
    });

    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role: 'admin' } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update user role' });
      }
    });

    // Ban / unban user
    app.patch('/users/ban/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { banned } = req.body;
        const result = await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { banned: !!banned } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update ban status' });
      }
    });

    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await userCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete user' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  PRODUCTS
    // ═══════════════════════════════════════════════════════════════════════════
    app.get('/products', async (req, res) => {
      try {
        const { category, search, sort, page = 1, limit = 20 } = req.query;

        // completely disable caching
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');

        let query = {};
        if (category && category !== 'all') query.category = category;
        if (search) {
          query.$or = [
            { title: { $regex: search, $options: 'i' } },
            { description: { $regex: search, $options: 'i' } },
          ];
        }
        let sortObj = { createdAt: -1 };
        if (sort === 'price_asc') sortObj = { price: 1 };
        if (sort === 'price_desc') sortObj = { price: -1 };
        if (sort === 'popular') sortObj = { sold: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const [products, total] = await Promise.all([
          productCollection.find(query).sort(sortObj).skip(skip).limit(parseInt(limit)).toArray(),
          productCollection.countDocuments(query),
        ]);
        const payload = { products, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) };
        res.send(payload);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch products' });
      }
    });

    app.get('/products/:id', async (req, res) => {
      try {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');

        const product = await productCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!product) return res.status(404).send({ message: 'Product not found' });
        res.send(product);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch product' });
      }
    });

    app.post('/products', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const product = {
          ...req.body,
          sold: 0,
          createdAt: new Date(),
          free_delivery_enabled: req.body.free_delivery_enabled === true,
          free_delivery_min_amount: Number(req.body.free_delivery_min_amount) || 0,
        };
        const result = await productCollection.insertOne(product);
        appCache.flushAll(); // Invalidate all product caches on write
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to create product' });
      }
    });

    app.put('/products/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const updatePayload = {
          ...req.body,
          updatedAt: new Date(),
          free_delivery_enabled: req.body.free_delivery_enabled === true,
          free_delivery_min_amount: Number(req.body.free_delivery_min_amount) || 0,
        };
        const result = await productCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: updatePayload }
        );
        appCache.flushAll();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update product' });
      }
    });

    // ── Admin: update only delivery settings for a product (instant, no redeploy) ──
    app.patch('/products/:id/delivery-settings', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { free_delivery_enabled, free_delivery_min_amount } = req.body;
        if (typeof free_delivery_enabled !== 'boolean') {
          return res.status(400).send({ message: 'free_delivery_enabled must be a boolean' });
        }
        const result = await productCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              free_delivery_enabled,
              free_delivery_min_amount: Number(free_delivery_min_amount) || 0,
              updatedAt: new Date(),
            },
          }
        );
        appCache.flushAll(); // Force cache refresh so next preview sees the new rule
        logger.info('Product delivery settings updated', {
          productId: req.params.id,
          free_delivery_enabled,
          free_delivery_min_amount,
          by: req.decoded.email,
        });
        res.send(result);
      } catch (error) {
        logger.error('Failed to update product delivery settings', { error: error.message });
        res.status(500).send({ message: 'Failed to update product delivery settings' });
      }
    });

    app.delete('/products/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await productCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        appCache.flushAll();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete product' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  DELIVERY PREVIEW (live delivery charge calculation for cart/checkout)
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/delivery/preview', verifyToken, async (req, res) => {
      try {
        const { cartItems = [], deliveryLocation = '', city = '', address = '' } = req.body;

        if (!Array.isArray(cartItems) || cartItems.length === 0) {
          return res.send({ charge: 0, isFree: false, reason: null, resolvedZone: '', hints: [] });
        }

        // Use shared helper — reads from cache or DB
        const deliverySettings = await loadDeliverySettings();
        const zoneTiers = deliverySettings.zones || DEFAULT_ZONES;

        // Fetch fresh product data (prevents stale free_delivery fields from client)
        const productIds = cartItems
          .map(i => { try { return new ObjectId(i.productId || i._id); } catch { return null; } })
          .filter(Boolean);

        const freshProducts = productIds.length > 0
          ? await productCollection.find({ _id: { $in: productIds } }).toArray()
          : [];

        const productMap = {};
        freshProducts.forEach(p => { productMap[p._id.toString()] = p; });

        const enrichedItems = cartItems.map(item => {
          const pid = (item.productId || item._id || '').toString();
          const fresh = productMap[pid] || {};
          return {
            ...item,
            free_delivery_enabled: fresh.free_delivery_enabled ?? false,
            free_delivery_min_amount: fresh.free_delivery_min_amount ?? 0,
            title: fresh.title || item.title || '',
            price: fresh.price ?? item.price ?? 0,  // DB price takes priority (tamper-proof)
          };
        });

        const result = computeDelivery({
          cartItems: enrichedItems,
          zoneTiers,
          deliveryLocation,
          city,
          address,
        });

        res.send(result);
      } catch (error) {
        logger.error('Delivery preview failed', { error: error.message });
        res.status(500).send({ message: 'Failed to compute delivery preview' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  CART
    // ═══════════════════════════════════════════════════════════════════════════
    app.get('/carts', verifyToken, async (req, res) => {
      try {
        const email = req.query.email;
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const result = await cartCollection.find({ email }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch cart' });
      }
    });

    app.post('/carts', verifyToken, async (req, res) => {
      try {
        const cartItem = { ...req.body, addedAt: new Date() };
        // Check if already in cart
        const existing = await cartCollection.findOne({
          email: cartItem.email,
          productId: cartItem.productId,
        });
        if (existing) {
          // Increment quantity
          const result = await cartCollection.updateOne(
            { _id: existing._id },
            { $inc: { quantity: 1 } }
          );
          return res.send({ ...result, message: 'Quantity updated' });
        }
        const result = await cartCollection.insertOne({ ...cartItem, quantity: cartItem.quantity || 1 });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to add to cart' });
      }
    });

    app.patch('/carts/:id', verifyToken, async (req, res) => {
      try {
        const { quantity } = req.body;
        const result = await cartCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { quantity: parseInt(quantity) } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update cart item' });
      }
    });

    app.delete('/carts/:id', verifyToken, async (req, res) => {
      try {
        const result = await cartCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to remove from cart' });
      }
    });

    // Clear all cart items for a user (used after order placement)
    app.delete('/carts', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const result = await cartCollection.deleteMany({ email });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to clear cart' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  SETTINGS — Tiered Zone Delivery
    // ═══════════════════════════════════════════════════════════════════════════

    // Helper to load zone tiers — always reads from DB for delivery settings
    // (document is tiny; no benefit to caching it and risking stale admin changes)
    async function loadDeliverySettings() {
      const settings = await settingsCollection.findOne({ type: 'delivery' });
      return { zones: (settings && settings.zones) ? settings.zones : DEFAULT_ZONES };
    }

    app.get('/settings/delivery', async (req, res) => {
      try {
        const payload = await loadDeliverySettings();
        res.send(payload);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch delivery settings' });
      }
    });

    app.put('/settings/delivery', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { zones } = req.body;
        const validation = validateZoneTiers(zones);
        if (!validation.valid) {
          return res.status(400).send({ message: validation.error });
        }
        const result = await settingsCollection.updateOne(
          { type: 'delivery' },
          { $set: { zones, updatedAt: new Date() } },
          { upsert: true }
        );
        appCache.flushAll(); // Clear any lingering product-list caches when zone pricing changes
        logger.info('Delivery zone settings updated', { zoneCount: Object.keys(zones).length, by: req.decoded.email });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update delivery settings' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  ORDERS
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/orders', verifyToken, async (req, res) => {
      try {
        // ── Input validation ─────────────────────────────────────────────────
        const { deliveryLocation, items, customerName, phone, address } = req.body;
        if (!items || items.length === 0) {
          return res.status(400).send({ message: 'Order must contain at least one item.' });
        }
        if (!customerName || !phone || !address) {
          return res.status(400).send({ message: 'Name, phone, and address are required.' });
        }

        // ── Fetch fresh delivery settings (zone tiers) ──────────────────────
        const deliverySettings = await loadDeliverySettings();
        const zoneTiers = deliverySettings.zones || DEFAULT_ZONES;

        // ── Fetch fresh product data to enrich cart items (tamper-proof) ─────
        const productIds = items
          .map(i => { try { return new ObjectId(i.productId || i._id); } catch { return null; } })
          .filter(Boolean);

        const freshProducts = productIds.length > 0
          ? await productCollection.find({ _id: { $in: productIds } }).toArray()
          : [];

        const productMap = {};
        freshProducts.forEach(p => { productMap[p._id.toString()] = p; });

        const enrichedItems = items.map(item => {
          const pid = (item.productId || item._id || '').toString();
          const fresh = productMap[pid] || {};
          return {
            ...item,
            price: fresh.price ?? item.price ?? 0,
            free_delivery_enabled: fresh.free_delivery_enabled ?? false,
            free_delivery_min_amount: fresh.free_delivery_min_amount ?? 0,
            title: fresh.title || item.title || '',
          };
        });

        // ── Server-side delivery computation (overrides any client-sent value) ──
        const deliveryResult = computeDelivery({
          cartItems: enrichedItems,
          zoneTiers,
          deliveryLocation: req.body.deliveryLocation || '',
          city: req.body.city || '',
          address: req.body.address || '',
        });

        const subtotal = computeSubtotal(enrichedItems);
        const deliveryCharge = deliveryResult.charge;
        const totalAmount = subtotal + deliveryCharge;

        // ── Generate human-readable Order ID ─────────────────────────────────
        const orderIdString = `RLBD-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

        // ── Build order document (whitelisted fields) ─────────────────────────
        const order = {
          email: req.decoded.email,  // always use JWT email — never trust client
          customerName: req.body.customerName,
          phone: req.body.phone,
          altPhone: req.body.altPhone || '',
          address: req.body.address,
          deliveryAddress: req.body.deliveryAddress || req.body.address,
          city: req.body.city,
          notes: req.body.notes || '',
          items,
          deliveryLocation: req.body.deliveryLocation || '',
          orderIdString,
          subtotal,
          deliveryCharge,
          deliveryIsFree: deliveryResult.isFree,
          deliveryFreeReason: deliveryResult.reason,
          deliveryFreeProduct: deliveryResult.freeRuleProduct,
          totalAmount,
          status: 'pending',
          orderedAt: new Date(),
        };

        const result = await orderCollection.insertOne(order);
        // Clear the user's cart after placing order
        await cartCollection.deleteMany({ email: order.email });
        logger.info('New order placed', {
          orderId: orderIdString,
          email: order.email,
          totalAmount,
          deliveryCharge,
          deliveryFreeReason: deliveryResult.reason,
        });
        res.send(result);
      } catch (error) {
        logger.error('Failed to place order', { error: error.message });
        res.status(500).send({ message: 'Failed to place order' });
      }
    });

    app.get('/orders', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;
        // Admin gets all orders; user gets only their own
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (user?.role === 'admin') {
          const orders = await orderCollection.find({}).sort({ orderedAt: -1 }).toArray();
          return res.send(orders);
        }
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const orders = await orderCollection.find({ email }).sort({ orderedAt: -1 }).toArray();
        res.send(orders);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch orders' });
      }
    });

    app.get('/orders/:id', verifyToken, async (req, res) => {
      try {
        const order = await orderCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!order) return res.status(404).send({ message: 'Order not found' });
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (user?.role !== 'admin' && order.email !== req.decoded.email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        res.send(order);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch order' });
      }
    });

    app.patch('/orders/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { status } = req.body;
        const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
        if (!validStatuses.includes(status)) {
          return res.status(400).send({ message: 'Invalid status' });
        }
        const result = await orderCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status, updatedAt: new Date() } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update order status' });
      }
    });

    app.delete('/orders/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await orderCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).send({ message: 'Order not found' });
        res.send({ message: 'Order deleted successfully' });
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete order' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  PAYMENTS
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/payments', verifyToken, async (req, res) => {
      try {
        const { paymentMethod, transactionId } = req.body;

        // Prevent duplicate TxID for bkash_manual
        if (paymentMethod === 'bkash_manual' && transactionId) {
          const existingTx = await paymentCollection.findOne({ transactionId });
          if (existingTx) {
            return res.status(400).send({ message: 'Transaction ID already exists. Duplicate transaction detected.' });
          }
        }

        const payment = {
          ...req.body,
          createdAt: new Date(),
        };

        // Determine initial status based on payment method
        let orderStatus = 'pending';
        let paymentStatus = 'pending';

        if (paymentMethod === 'card') {
          paymentStatus = 'paid';
          orderStatus = 'processing';
          payment.paidAt = new Date();
        } else if (paymentMethod === 'bkash_manual') {
          paymentStatus = 'under_review';
          orderStatus = 'pending';
        } else if (paymentMethod === 'cod') {
          paymentStatus = 'pending';
          orderStatus = 'pending';
        }

        payment.status = paymentStatus;

        const result = await paymentCollection.insertOne(payment);

        // Update order status
        if (payment.orderId) {
          await orderCollection.updateOne(
            { _id: new ObjectId(payment.orderId) },
            { $set: { status: orderStatus, paymentStatus: paymentStatus } }
          );
        }
        logger.info('Payment recorded', { method: paymentMethod, status: paymentStatus, email: req.body.email });
        res.send(result);
      } catch (error) {
        logger.error('Failed to save payment', { error: error.message, email: req.body?.email });
        res.status(500).send({ message: 'Failed to save payment' });
      }
    });

    app.patch('/payments/:id/verify', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const paymentId = req.params.id;
        const payment = await paymentCollection.findOne({ _id: new ObjectId(paymentId) });
        if (!payment) return res.status(404).send({ message: 'Payment not found' });

        const result = await paymentCollection.updateOne(
          { _id: new ObjectId(paymentId) },
          { $set: { status: 'paid', paidAt: new Date(), verifiedBy: req.decoded.email } }
        );

        if (payment.orderId) {
          await orderCollection.updateOne(
            { _id: new ObjectId(payment.orderId) },
            { $set: { status: 'processing', paymentStatus: 'paid' } }
          );
        }

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to verify payment' });
      }
    });

    app.patch('/payments/:id/reject', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const paymentId = req.params.id;
        const payment = await paymentCollection.findOne({ _id: new ObjectId(paymentId) });
        if (!payment) return res.status(404).send({ message: 'Payment not found' });

        const result = await paymentCollection.updateOne(
          { _id: new ObjectId(paymentId) },
          { $set: { status: 'rejected', rejectedAt: new Date(), rejectedBy: req.decoded.email } }
        );

        if (payment.orderId) {
          await orderCollection.updateOne(
            { _id: new ObjectId(payment.orderId) },
            { $set: { status: 'cancelled', paymentStatus: 'rejected' } }
          );
        }

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to reject payment' });
      }
    });

    app.get('/payments', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (user?.role === 'admin') {
          // Sort by createdAt descending; paidAt may be absent for manual/COD payments
          const payments = await paymentCollection.find({}).sort({ createdAt: -1 }).toArray();
          return res.send(payments);
        }
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const payments = await paymentCollection.find({ email }).sort({ createdAt: -1 }).toArray();
        res.send(payments);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch payments' });
      }
    });

    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      try {
        if (!stripe) {
          return res.status(500).send({ message: 'Stripe is not configured in the backend environment' });
        }
        const { price } = req.body;
        if (!price || isNaN(price)) {
          return res.status(400).send({ message: 'Invalid price' });
        }
        // BDT is a zero-decimal currency in Stripe — do NOT multiply by 100
        const amount = Math.round(price); // send the raw taka amount
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: 'bdt',
          payment_method_types: ['card'],
        });
        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error('Stripe error:', error);
        res.status(500).send({ message: 'Failed to create payment intent' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  ADMIN STATS
    // ═══════════════════════════════════════════════════════════════════════════
    app.get('/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const [
          totalUsers,
          totalProducts,
          totalOrders,
          totalRevenue,
          recentOrders,
          pendingOrders,
          deliveredOrders,
        ] = await Promise.all([
          userCollection.countDocuments(),
          productCollection.countDocuments(),
          orderCollection.countDocuments(),
          paymentCollection.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } },
          ]).toArray(),
          orderCollection.find({}).sort({ orderedAt: -1 }).limit(6).toArray(),
          orderCollection.countDocuments({ status: 'pending' }),
          orderCollection.countDocuments({ status: 'delivered' }),
        ]);

        // Weekly revenue for chart (last 7 days)
        const weeklyData = [];
        for (let i = 6; i >= 0; i--) {
          const start = new Date();
          start.setDate(start.getDate() - i);
          start.setHours(0, 0, 0, 0);
          const end = new Date(start);
          end.setHours(23, 59, 59, 999);

          const [rev, orders] = await Promise.all([
            paymentCollection.aggregate([
              { $match: { paidAt: { $gte: start, $lte: end } } },
              { $group: { _id: null, total: { $sum: '$amount' } } },
            ]).toArray(),
            orderCollection.countDocuments({ orderedAt: { $gte: start, $lte: end } }),
          ]);
          weeklyData.push({
            day: start.toLocaleDateString('en-BD', { weekday: 'short' }),
            revenue: rev[0]?.total || 0,
            orders,
          });
        }

        res.send({
          totalUsers,
          totalProducts,
          totalOrders,
          totalRevenue: totalRevenue[0]?.total || 0,
          recentOrders,
          pendingOrders,
          deliveredOrders,
          weeklyData,
        });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch stats', error: error.message });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  PROFILES
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/profiles', verifyToken, async (req, res) => {
      try {
        const profile = req.body;
        const existing = await profileCollection.findOne({ email: profile.email });
        if (existing) return res.status(400).send({ message: 'Profile already exists' });
        const result = await profileCollection.insertOne({ ...profile, createdAt: new Date() });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to create profile' });
      }
    });

    app.get('/profiles/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          const requester = await userCollection.findOne({ email: req.decoded.email });
          if (requester?.role !== 'admin') return res.status(403).send({ message: 'forbidden access' });
        }
        const result = await profileCollection.findOne({ email });
        res.send(result || null);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch profile' });
      }
    });

    app.put('/profiles/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const update = req.body;
        const filter = { _id: new ObjectId(id) };
        const profile = await profileCollection.findOne(filter);
        if (!profile) return res.status(404).send({ message: 'Profile not found' });
        if (req.decoded.email !== profile.email) {
          const requester = await userCollection.findOne({ email: req.decoded.email });
          if (requester?.role !== 'admin') return res.status(403).send({ message: 'forbidden access' });
        }
        const result = await profileCollection.updateOne(filter, { $set: { ...update, updatedAt: new Date() } });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update profile' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  FEATURED / MOST POPULAR PRODUCTS (admin-controlled)
    // ═══════════════════════════════════════════════════════════════════════════
    // GET — public, returns full product details for all featured items
    app.get('/featured-products', async (req, res) => {
      try {
        const cacheKey = 'featured:products';
        const cached = appCache.get(cacheKey);
        if (cached) return res.send(cached);

        const featuredDocs = await featuredCollection.find({}).sort({ addedAt: -1 }).toArray();
        if (featuredDocs.length === 0) return res.send([]);

        // Batch-fetch all product details in one query (no N+1)
        const productIds = featuredDocs.map(f => new ObjectId(f.productId));
        const products = await productCollection
          .find({ _id: { $in: productIds } })
          .toArray();

        // Preserve the admin-defined order
        const productMap = {};
        products.forEach(p => { productMap[p._id.toString()] = p; });
        const ordered = featuredDocs
          .map(f => productMap[f.productId])
          .filter(Boolean);

        appCache.set(cacheKey, ordered, 120); // 2 min TTL
        res.send(ordered);
      } catch (error) {
        logger.error('Failed to fetch featured products', { error: error.message });
        res.status(500).send({ message: 'Failed to fetch featured products' });
      }
    });

    // POST — admin adds a product to the featured list
    app.post('/featured-products', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { productId } = req.body;
        if (!productId) return res.status(400).send({ message: 'productId is required' });

        // Validate product exists
        const product = await productCollection.findOne({ _id: new ObjectId(productId) });
        if (!product) return res.status(404).send({ message: 'Product not found' });

        const existing = await featuredCollection.findOne({ productId });
        if (existing) return res.status(409).send({ message: 'Product is already featured' });

        const result = await featuredCollection.insertOne({
          productId,
          productTitle: product.title,
          addedAt: new Date(),
          addedBy: req.decoded.email,
        });
        appCache.del('featured:products');
        logger.info('Product added to featured', { productId, by: req.decoded.email });
        res.send(result);
      } catch (error) {
        logger.error('Failed to add featured product', { error: error.message });
        res.status(500).send({ message: 'Failed to add featured product' });
      }
    });

    // DELETE — admin removes a product from featured list
    app.delete('/featured-products/:productId', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { productId } = req.params;
        const result = await featuredCollection.deleteOne({ productId });
        if (result.deletedCount === 0) return res.status(404).send({ message: 'Featured product not found' });
        appCache.del('featured:products');
        logger.info('Product removed from featured', { productId, by: req.decoded.email });
        res.send({ message: 'Removed from featured successfully' });
      } catch (error) {
        logger.error('Failed to remove featured product', { error: error.message });
        res.status(500).send({ message: 'Failed to remove featured product' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  CONTACT
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/contactCollection', async (req, res) => {
      try {
        const form = req.body || {};
        if (!form.name || !form.email || !form.message) {
          return res.status(400).send({ message: 'Name, email, and message are required' });
        }
        const payload = {
          name: String(form.name).trim(),
          email: String(form.email).toLowerCase().trim(),
          phone: form.phone ? String(form.phone).trim() : '',
          subject: form.subject ? String(form.subject).trim() : '',
          message: String(form.message).trim(),
          createdAt: new Date(),
        };
        const result = await contactCollection.insertOne(payload);
        res.send({ insertedId: result.insertedId, message: 'Message sent successfully!' });
      } catch (e) {
        res.status(500).send({ message: 'Failed to send message', error: e?.message });
      }
    });

    app.get('/contactCollection', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await contactCollection.find().sort({ createdAt: -1 }).toArray();
        res.send(result);
      } catch (e) {
        res.status(500).send({ message: 'Failed to fetch contacts' });
      }
    });

    app.delete('/contactCollection/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await contactCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).send({ message: 'Contact not found' });
        res.send({ message: 'Contact deleted successfully' });
      } catch (e) {
        res.status(500).send({ message: 'Failed to delete contact' });
      }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    //  BLOGS
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/blogs', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const blog = {
          ...req.body,
          views: 0,
          comments: 0,
          createdAt: new Date(),
        };
        const result = await blogCollection.insertOne(blog);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to create blog post' });
      }
    });

    app.get('/blogs', async (req, res) => {
      try {
        const cached = appCache.get('blogs:all');
        if (cached) return res.send(cached);
        const blogs = await blogCollection.find().sort({ createdAt: -1 }).toArray();
        appCache.set('blogs:all', blogs, 120); // 2 min TTL
        res.send(blogs);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch blogs' });
      }
    });

    app.delete('/blogs/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await blogCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        appCache.del('blogs:all');
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete blog post' });
      }
    });

    app.put('/blogs/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { _id, ...updatedData } = req.body;
        const result = await blogCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: updatedData }
        );
        appCache.del('blogs:all');
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update blog post' });
      }
    });

    // Signal that all routes are registered and DB is ready
    dbReady = true;
    _resolveReady();
    logger.info('✅ All routes registered. Server ready.');

    // Auto-cancel unpaid orders after 30 minutes
    setInterval(async () => {
      try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        await orderCollection.updateMany(
          { status: 'pending', paymentStatus: { $exists: false }, orderedAt: { $lt: thirtyMinutesAgo } },
          { $set: { status: 'cancelled', autoCancelledAt: new Date() } }
        );
      } catch (err) {
        console.error("Failed to auto-cancel orders", err);
      }
    }, 15 * 60 * 1000); // Check every 15 mins

  } catch (error) {
    console.error('MongoDB connection error:', error);
    // Resolve the gate even on error so requests get a proper error instead of hanging
    _resolveReady();
  }
}

run().catch(console.error);

// Root
app.get('/', (req, res) => {
  res.send('Redleaf-BD API is running 🍃');
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled Express Error', { error: err.message, stack: err.stack, url: req.url });
  res.status(500).send({ message: 'Something went wrong!', error: err.message });
});

// Start server (local dev only)
if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`Redleaf-BD server running on port ${port}`);
  });
}

module.exports = app;