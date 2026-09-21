const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// FIX: stripe আগে কোথাও require করা ছিল না
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 4000;
const jwtSecret = process.env.ACCESS_TOKEN_SECRET;

// ====================================================
// Firebase Admin
// ====================================================
if (!admin.apps.length) {
    try {
        const serviceKey = process.env.FIREBASE_SERVICE_KEY;
        if (serviceKey) {
            const decoded = Buffer.from(serviceKey, 'base64').toString('utf8');
            admin.initializeApp({
                credential: admin.credential.cert(JSON.parse(decoded)),
            });
        } else {
            console.warn('⚠️ FIREBASE_SERVICE_KEY not set');
        }
    } catch (error) {
        console.error('❌ Firebase Init Error:', error.message);
    }
}

// ====================================================
// Middleware
// ====================================================
app.use(cors({
    // যেকোনো client domain এখানে যোগ করতে হবে, নাহলে ব্রাউজার ব্লক করবে
    origin: [
        'http://localhost:5173',
        'https://bd-blood-donar-2025.web.app',
        'https://bd-blood-donar-2025.firebaseapp.com',
    ],
    credentials: true,
}));
app.use(express.json());

// ====================================================
// Districts data — fs.readFileSync এর বদলে require (serverless-safe)
// ====================================================
let districtsData = [];
try {
    districtsData = require('./districts.json');
} catch (error) {
    console.warn('⚠️ districts.json load failed');
}

// ====================================================
// MongoDB — connection cache করা হচ্ছে (serverless এ প্রতি request এ
// নতুন connection খুললে Atlas এর connection limit শেষ হয়ে যায়)
// ====================================================
const uri = process.env.MONGODB_URI;
if (!uri) console.error('❌ MONGODB_URI missing! Vercel env variable set করো।');

const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let db;
let connecting;

async function getDb() {
    if (db) return db;
    if (!connecting) {
        connecting = client.connect().then((c) => {
            db = c.db('bloodDonarDB');
            console.log('🟢 MongoDB connected');
            return db;
        }).catch((err) => {
            connecting = null; // পরের request এ আবার try করবে
            throw err;
        });
    }
    return connecting;
}

const collections = {
    users: async () => (await getDb()).collection('users'),
    donations: async () => (await getDb()).collection('donationRequests'),
    payments: async () => (await getDb()).collection('payments'),
    blogs: async () => (await getDb()).collection('blogs'), // FIX: আগে define করা ছিল না
};

// ====================================================
// Auth Middlewares
// ====================================================
const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'Unauthorized access: Missing token' });
    }
    const token = authorization.split(' ')[1];
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).send({ error: true, message: 'Unauthorized access: Invalid token' });
        }
        req.decoded = decoded;
        next();
    });
};

const verifyAdmin = async (req, res, next) => {
    try {
        const userCollections = await collections.users();
        const user = await userCollections.findOne({ email: req.decoded.email });
        if (user?.role !== 'admin') {
            return res.status(403).send({ error: true, message: 'Forbidden: Admin only!' });
        }
        next();
    } catch (error) {
        res.status(500).send({ message: 'Admin check failed' });
    }
};

// ====================================================
// A. AUTH & USER APIs
// ====================================================

// FIX: আসল authentication Firebase দিয়ে হচ্ছে (client-side)।
// এই backend শুধু MongoDB-তে profile তথ্য রাখে, তাই password/bcrypt লাগবে না।
app.post('/users/register', async (req, res) => {
    try {
        const userCollections = await collections.users();
        const userInfo = req.body;
        const { email } = userInfo;

        if (!email) {
            return res.status(400).send({ message: 'Email is required' });
        }

        const existingUser = await userCollections.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: 'User already exists with this email' });
        }

        const newUser = {
            ...userInfo,
            role: userInfo.role || 'donor',
            status: userInfo.status || 'active',
            createdAt: new Date(),
        };

        const result = await userCollections.insertOne(newUser);
        const token = jwt.sign(
            { email: newUser.email, role: newUser.role, name: newUser.name },
            jwtSecret,
            { expiresIn: '7d' }
        );

        res.send({
            insertedId: result.insertedId,
            user: {
                email: newUser.email,
                role: newUser.role,
                name: newUser.name,
                image: newUser.avatar || newUser.image,
                status: newUser.status,
            },
            token,
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send({ message: 'Error during user registration', error: error.message });
    }
});

// FIX: password compare বাদ — Firebase আগেই login verify করে ফেলেছে,
// এই রুট শুধু MongoDB থেকে profile/role/token ফেরত দেয়।
app.post('/users/login', async (req, res) => {
    try {
        const userCollections = await collections.users();
        const { email } = req.body;

        if (!email) {
            return res.status(400).send({ message: 'Email is required' });
        }

        const user = await userCollections.findOne({ email });
        if (!user) return res.status(401).send({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { email: user.email, role: user.role, name: user.name },
            jwtSecret,
            { expiresIn: '7d' }
        );

        res.send({
            user: {
                email: user.email,
                role: user.role,
                name: user.name,
                image: user.avatar || user.image,
                status: user.status,
            },
            token,
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send({ message: 'Error during login' });
    }
});

// ⚠️ গুরুত্বপূর্ণ: নিচের specific রুটগুলো অবশ্যই '/users/:email' এর
// আগে থাকতে হবে। নাহলে Express "search" আর "admin" কে :email ধরে নেয়।

app.get('/users/search', async (req, res) => {
    try {
        const userCollections = await collections.users();
        const { bloodGroup, district } = req.query;
        const query = { role: 'donor', status: 'active' };
        if (bloodGroup) query.bloodGroup = bloodGroup;
        if (district) query.district = district;

        const donors = await userCollections.find(query).toArray();
        res.send(donors);
    } catch (error) {
        console.error('Search API Error:', error);
        res.status(500).send({ message: 'Searching donors failed!' });
    }
});

app.get('/users/admin/:email', async (req, res) => {
    try {
        const userCollections = await collections.users();
        const user = await userCollections.findOne({ email: req.params.email });
        res.send({ admin: user?.role === 'admin' });
    } catch (error) {
        res.status(500).send({ message: 'Admin check failed' });
    }
});

app.patch('/users/admin/:id', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const userCollections = await collections.users();
        const result = await userCollections.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { role: 'admin' } }
        );
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Role update failed' });
    }
});

app.patch('/users/status/:id', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const userCollections = await collections.users();
        const result = await userCollections.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status: req.body.status } }
        );
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Status update failed' });
    }
});

app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const userCollections = await collections.users();
        res.send(await userCollections.find().toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch users' });
    }
});

// এই dynamic রুটটা সবার শেষে
app.get('/users/:email', verifyJWT, async (req, res) => {
    try {
        const userCollections = await collections.users();
        const email = req.params.email;
        if (req.decoded.email !== email) {
            return res.status(403).send({ message: 'Forbidden access: Token mismatch' });
        }
        const user = await userCollections.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found' });

        const { password, ...userData } = user;
        res.send(userData);
    } catch (error) {
        console.error('User check error:', error);
        res.status(500).send({ message: 'Internal server error' });
    }
});

app.get('/user/:email', verifyJWT, async (req, res) => {
    try {
        const userCollections = await collections.users();
        res.send(await userCollections.findOne({ email: req.params.email }));
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user' });
    }
});

app.patch('/user/update/:email', verifyJWT, async (req, res) => {
    try {
        const userCollections = await collections.users();
        const d = req.body;
        const result = await userCollections.updateOne(
            { email: req.params.email },
            { $set: {
                name: d.name,
                phone: d.phone,
                district: d.district,
                upazila: d.upazila,
                bloodGroup: d.bloodGroup,
            } }
        );
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Profile update failed' });
    }
});

// ====================================================
// B. DONATION REQUEST APIs
// ====================================================

// '/donation-requests/:id' এর আগে থাকতেই হবে
app.get('/donation-requests/featured', async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const featured = await donationCollections
            .find({ donationStatus: 'pending' })
            .sort({ createdAt: -1 })
            .limit(3)
            .toArray();
        res.send(featured);
    } catch (error) {
        console.error('Error fetching featured requests:', error);
        res.status(500).send({ message: 'Failed to fetch featured requests', error: error.message });
    }
});

app.get('/donation-requests', async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const query = req.query.status === 'pending' ? { donationStatus: 'pending' } : {};
        const requests = await donationCollections.find(query).sort({ createdAt: -1 }).toArray();
        res.send(requests);
    } catch (error) {
        console.error('Error fetching donation requests:', error);
        res.status(500).send({ message: 'Failed to fetch donation requests' });
    }
});

app.get('/all-request', async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const query = req.query.status === 'pending' ? { donationStatus: 'pending' } : {};
        res.send(await donationCollections.find(query).sort({ createdAt: -1 }).toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch donation requests' });
    }
});

app.get('/all-donation-requests', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        res.send(await donationCollections.find().toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch requests' });
    }
});

app.post('/donation-requests', async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const newRequest = {
            ...req.body,
            donationStatus: 'pending',
            createdAt: new Date(),
        };
        res.send(await donationCollections.insertOne(newRequest));
    } catch (error) {
        console.error('Error creating donation request:', error);
        res.status(500).send({ message: 'Failed to create request' });
    }
});

app.patch('/donation-requests/status/:id', verifyJWT, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const id = req.params.id;
        const { status, donor } = req.body;

        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid ID format' });

        const filter = { _id: new ObjectId(id) };
        const request = await donationCollections.findOne(filter);
        if (!request) return res.status(404).send({ message: 'Donation request not found.' });

        if (request.donationStatus !== 'pending' || status !== 'inprogress') {
            return res.status(400).send({ message: 'Invalid status transition.' });
        }
        if (!donor || donor.email !== req.decoded.email) {
            return res.status(403).send({ message: 'Forbidden: Donor email mismatch.' });
        }

        const result = await donationCollections.updateOne(filter, {
            $set: {
                donationStatus: 'inprogress',
                donorName: donor.name,
                donorEmail: donor.email,
                donornumber: donor.number,
            },
        });
        res.send({ success: true, modifiedCount: result.modifiedCount });
    } catch (error) {
        console.error('Update Status Error:', error);
        res.status(500).send({ message: 'Internal server error during status update' });
    }
});

app.patch('/donation-requests/update-status/:id', verifyJWT, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const result = await donationCollections.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { donationStatus: req.body.status } }
        );
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Status update failed' });
    }
});

app.get('/donation-requests/:id', verifyJWT, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid ID format' });

        const request = await donationCollections.findOne({ _id: new ObjectId(id) });
        if (!request) return res.status(404).send({ message: 'Donation request not found.' });
        res.send(request);
    } catch (error) {
        console.error('Get Single Request Error:', error);
        res.status(500).send({ message: 'Internal server error' });
    }
});

app.delete('/donation-requests/:id', verifyJWT, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        res.send(await donationCollections.deleteOne({ _id: new ObjectId(req.params.id) }));
    } catch (error) {
        res.status(500).send({ message: 'Delete failed' });
    }
});

app.patch('/update-request/:id', verifyJWT, async (req, res) => {
    try {
        const donationCollections = await collections.donations();
        res.send(await donationCollections.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body }
        ));
    } catch (error) {
        res.status(500).send({ message: 'Update failed' });
    }
});

app.get('/my-requests/:email', verifyJWT, async (req, res) => {
    try {
        if (req.decoded.email !== req.params.email) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        const donationCollections = await collections.donations();
        res.send(await donationCollections
            .find({ requesterEmail: req.params.email })
            .sort({ createdAt: -1 })
            .toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch requests' });
    }
});

app.get('/my-donations/:email', verifyJWT, async (req, res) => {
    try {
        if (req.decoded.email !== req.params.email) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        const donationCollections = await collections.donations();
        res.send(await donationCollections.find({ donorEmail: req.params.email }).toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch donations' });
    }
});

// ====================================================
// C. SEARCH / DONOR / STATS
// ====================================================

app.get('/search-donors', async (req, res) => {
    try {
        const userCollections = await collections.users();
        const { bloodGroup, district, upazila } = req.query;
        const query = { role: 'donor' };
        if (bloodGroup) query.bloodGroup = bloodGroup;
        if (district) query.district = district;
        if (upazila) query.upazila = upazila;
        res.send(await userCollections.find(query).toArray());
    } catch (error) {
        res.status(500).send({ message: 'Search failed' });
    }
});

app.get('/donor-details/:id', async (req, res) => {
    try {
        const userCollections = await collections.users();
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).send({ message: 'Invalid ID format' });
        }
        const result = await userCollections.findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { name: 1, email: 1, image: 1, bloodGroup: 1, district: 1, upazila: 1, phone: 1 } }
        );
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch donor' });
    }
});

app.get('/admin-stats', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const userCollections = await collections.users();
        const donationCollections = await collections.donations();
        res.send({
            totalUsers: await userCollections.estimatedDocumentCount(),
            totalRequests: await donationCollections.estimatedDocumentCount(),
            pendingRequests: await donationCollections.countDocuments({ donationStatus: 'pending' }),
            totalDonors: await userCollections.countDocuments({ role: 'donor' }),
        });
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch stats' });
    }
});

app.get('/public/districts', (req, res) => {
    if (districtsData.length > 0) return res.send(districtsData);
    res.status(404).send({ message: 'Administrative data not available.' });
});

app.get('/blogs', async (req, res) => {
    try {
        const blogCollections = await collections.blogs();
        res.send(await blogCollections
            .find({ status: 'published' })
            .sort({ createdAt: -1 })
            .toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch blogs' });
    }
});

// ====================================================
// D. PAYMENT APIs
// ====================================================

app.post('/create-payment-intent', async (req, res) => {
    try {
        const amount = Math.round(req.body.price * 100);
        const paymentIntent = await stripe.paymentIntents.create({
            amount,
            currency: 'bdt',
            payment_method_types: ['card'],
        });
        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        console.error('Stripe error:', err);
        res.status(500).send({ error: 'Stripe PaymentIntent creation failed' });
    }
});

app.post('/payments', async (req, res) => {
    try {
        const paymentCollection = await collections.payments();
        const payment = req.body;
        if (!payment.amount || !payment.name || !payment.method) {
            return res.status(400).send({ error: 'amount, name, method required.' });
        }
        if (!payment.transactionId) {
            payment.transactionId = `${payment.method}-${Date.now()}`;
        }
        payment.date = new Date();
        res.send(await paymentCollection.insertOne(payment));
    } catch (err) {
        console.error('Save payment error:', err);
        res.status(500).send({ error: 'Internal server error' });
    }
});

app.get('/payments', async (req, res) => {
    try {
        const paymentCollection = await collections.payments();
        res.send(await paymentCollection.find().sort({ date: -1 }).toArray());
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch payments' });
    }
});

app.get('/payments/total', async (req, res) => {
    try {
        const paymentCollection = await collections.payments();
        const result = await paymentCollection
            .aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }])
            .toArray();
        res.send({ total: result[0]?.total || 0 });
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch total' });
    }
});

// ====================================================
// ROOT + 404 + START
// ====================================================

app.get('/', (req, res) => {
    res.send('🩸 Blood Donor Server is Running and Ready for Action! 🚀');
});

// কোন রুট না মিললে পরিষ্কার মেসেজ (debug এ কাজে লাগবে)
app.use((req, res) => {
    res.status(404).send({ message: `Route not found: ${req.method} ${req.originalUrl}` });
});

// Vercel serverless এর জন্য export, লোকালে listen
module.exports = app;

if (require.main === module) {
    app.listen(port, () => console.log(`Server is running on port ${port}`));
}