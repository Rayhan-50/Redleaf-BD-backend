const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
} else {
  console.warn("STRIPE_SECRET_KEY is missing in environment variables.");
}
// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const port = process.env.PORT || 5000;

// CORS
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'https://redleaf-bd.vercel.app',
    process.env.CLIENT_ADDRESS,
    process.env.DEV_CLIENT,
  ].filter(Boolean),
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' } }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
});
app.use(limiter);

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.rxvwb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
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
        const { search, role } = req.query;
        let query = {};
        if (search) {
          query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ];
        }
        if (role && role !== 'all') query.role = role;
        const result = await userCollection.find(query).toArray();
        res.send(result);
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
        res.send({ products, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch products' });
      }
    });

    app.get('/products/:id', async (req, res) => {
      try {
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
        };
        const result = await productCollection.insertOne(product);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to create product' });
      }
    });

    app.put('/products/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await productCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { ...req.body, updatedAt: new Date() } }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to update product' });
      }
    });

    app.delete('/products/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const result = await productCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete product' });
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
    //  ORDERS
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/orders', verifyToken, async (req, res) => {
      try {
        const order = {
          ...req.body,
          status: 'pending',
          orderedAt: new Date(),
        };
        const result = await orderCollection.insertOne(order);
        // Clear the user's cart after placing order
        await cartCollection.deleteMany({ email: order.email });
        res.send(result);
      } catch (error) {
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

    // ═══════════════════════════════════════════════════════════════════════════
    //  PAYMENTS
    // ═══════════════════════════════════════════════════════════════════════════
    app.post('/payments', verifyToken, async (req, res) => {
      try {
        const payment = { ...req.body, paidAt: new Date() };
        const result = await paymentCollection.insertOne(payment);
        // Update order status to processing after payment
        if (payment.orderId) {
          await orderCollection.updateOne(
            { _id: new ObjectId(payment.orderId) },
            { $set: { status: 'processing', paidAt: new Date() } }
          );
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to save payment' });
      }
    });

    app.get('/payments', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (user?.role === 'admin') {
          const payments = await paymentCollection.find({}).sort({ paidAt: -1 }).toArray();
          return res.send(payments);
        }
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const payments = await paymentCollection.find({ email }).sort({ paidAt: -1 }).toArray();
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
        const amount = parseInt(price * 100); // converting to cents
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

  } catch (error) {
    console.error('MongoDB connection error:', error);
  }
}

run().catch(console.error);

// Root
app.get('/', (req, res) => {
  res.send('Redleaf-BD API is running 🍃');
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({ message: 'Something went wrong!', error: err.message });
});

// Start server (local dev only)
if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`Redleaf-BD server running on port ${port}`);
  });
}

module.exports = app;