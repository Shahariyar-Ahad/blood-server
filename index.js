const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs'); 
const path = require('path'); 
const admin = require('firebase-admin'); 

require('dotenv').config(); 
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const port = process.env.PORT || 4000; 
const app = express();
if (!admin.apps.length) {
    try {
        const serviceKey = process.env.FIREBASE_SERVICE_KEY;
        if (serviceKey) {
            const decoded = Buffer.from(serviceKey, "base64").toString("utf8");
            const serviceAccount = JSON.parse(decoded);
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
            console.log("✅ Firebase Admin Initialized via Environment Variable!");
        } else {
            console.warn("⚠️ Warning: FIREBASE_SERVICE_KEY not found in .env");
        }
    } catch (error) {
        console.error("❌ Firebase Initialization Error:", error.message);
    }
}

// Configuration
const jwtSecret = process.env.ACCESS_TOKEN_SECRET; 
const districtsFilePath = path.join(__dirname, 'districts.json'); 
let districtsData = []; 

// Middleware
app.use(cors({
    origin: [
        'http://localhost:5173',
         'https://bd-blood-donar-2025.web.app'
    ], 
    credentials: true,
}));
app.use(express.json());

// ====================================================
// ১. প্রশাসনিক ডেটা লোড করা
// ====================================================

try {
    const rawData = fs.readFileSync(districtsFilePath);
    districtsData = JSON.parse(rawData);
    console.log("✅ Districts data loaded successfully from JSON.");
} catch (error) {
    console.warn("⚠️ WARNING: districts.json file not found or failed to load.");
}

// ====================================================
// ২. MongoDB Client Setup
// ====================================================

const uri = process.env.MONGODB_URI; 
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// ====================================================
// ৩. JWT Middleware: প্রাইভেট API সুরক্ষিত করার জন্য
// ====================================================
const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'Unauthorized access: Missing token' });
    }
    const token = authorization.split(' ')[1];

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            console.error("JWT verification error:", err.message);
            return res.status(401).send({ error: true, message: 'Unauthorized access: Invalid token' });
        }
        req.decoded = decoded; 
        next();
    });
};


async function run() {
    try {
         await client.connect();
        
        const database = client.db('bloodDonarDB'); 
        const userCollections = database.collection('users');
        const donationCollections = database.collection('donationRequests');
        const paymentCollection = database.collection('payments');
        // ----------------------------------------------------
        // A. AUTHENTICATION & USER APIs
        // ----------------------------------------------------

        
      // ১. রেজিস্ট্রেশন (ইউজার তৈরি) API: /users/register (Public)
app.post('/users/register', async (req, res) => {
    try {
        const userInfo = req.body;
        const { email, password, name, image } = userInfo; // image ফিল্ডটি ফ্রন্টএন্ড থেকে আসবে

        // ইউজার আগে থেকেই আছে কিনা চেক করা
        const existingUser = await userCollections.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: 'User already exists with this email' });
        }

        // পাসওয়ার্ড হ্যাশ করা
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // নতুন ইউজার অবজেক্ট তৈরি
        const newUser = {
            ...userInfo,
            password: hashedPassword,
            role: 'donor',    // ডিফল্ট রোল
            status: 'active', // ডিফল্ট স্ট্যাটাস
            createdAt: new Date(),
        };

        // ডাটাবেজে সেভ করা
        const result = await userCollections.insertOne(newUser);
        
        // টোকেন তৈরি করা (Payload-এ সব জরুরি তথ্য রাখা হয়েছে)
        const token = jwt.sign(
            { email: newUser.email, role: newUser.role, name: newUser.name }, 
            jwtSecret, 
            { expiresIn: '7d' }
        );

        // ফ্রন্টএন্ডে ইউজার ডাটা এবং টোকেন পাঠানো
        // এখানে image: newUser.image পাঠানোই মূল সমাধান
        res.send({ 
            insertedId: result.insertedId, 
            user: { 
                email: newUser.email, 
                role: newUser.role, 
                name: newUser.name, 
                image: newUser.image, // এটিই আপনার রিফ্রেশ সমস্যা সমাধান করবে
                status: newUser.status 
            }, 
            token: token 
        });

    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send({ message: 'Error during user registration', error: error.message });
    }
});

        // ২. লগইন (টোকেন জেনারেশন) API
app.post('/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userCollections.findOne({ email });

        if (!user) {
            return res.status(401).send({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send({ message: 'Password does not match' });
        }

        const token = jwt.sign({ email: user.email, role: user.role, name: user.name }, jwtSecret, { expiresIn: '7d' });

        // ইমেজ সহ সব দরকারি ডাটা পাঠান
        res.send({ 
            user: { 
                email: user.email, 
                role: user.role, 
                name: user.name, 
                image: user.image, // এটি যোগ করা হয়েছে
                status: user.status 
            }, 
            token 
        });
    } catch (error) {
        res.status(500).send({ message: 'Error during login' });
    }
});
        
        // **৩. ইউজার তথ্য / রোল চেক API: /users/:email (Private) - 404 ফিক্স**
        app.get('/users/:email', verifyJWT, async (req, res) => {
            try {
                const email = req.params.email;
                // টোকেন যাচাই করা হচ্ছে
                if (req.decoded.email !== email) {
                    return res.status(403).send({ message: 'Forbidden access: Token mismatch' });
                }

                const user = await userCollections.findOne({ email });
                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // নিরাপত্তার জন্য পাসওয়ার্ড সরিয়ে দেওয়া হলো
                const { password, ...userData } = user;
                res.send(userData);

            } catch (error) {
                console.error("User check error:", error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // ----------------------------------------------------
        // B. DONATION REQUEST APIs (Public & Private)
        // ----------------------------------------------------

        // **৪. ফিচার্ড ডোনেশন রিকোয়েস্ট লোড করা (Public) - 401 ফিক্স**
        // ফ্রন্টএন্ডে কল: /donation-requests/featured 
        app.get('/donation-requests/featured', async (req, res) => { 
            try {
                // শুধুমাত্র 'pending' স্ট্যাটাসের রিকোয়েস্টগুলোই ফিচার্ড হিসেবে দেখান
                const featured = await donationCollections.find({ donationStatus: 'pending' })
                    .sort({ requestDate: -1 }) 
                    .limit(3) // হোম পেজের জন্য প্রথম ৩টি দেখানো হচ্ছে
                    .toArray();

                res.send(featured);
            } catch (error) {
                console.error("Error fetching featured requests:", error);
                res.status(500).send({ message: "Failed to fetch featured requests from database." });
            }
        });


        // ৫. সমস্ত ডোনেশন রিকোয়েস্ট লোড করা (Public, Filterable)
        // ফ্রন্টএন্ডে কল: /donation-requests?status=pending 
        app.get('/donation-requests', async (req, res) => {
            const { status } = req.query; 
            const query = {};

            if (status === 'pending') {
                query.donationStatus = 'pending'; 
            }
            
            try {
                const requests = await donationCollections.find(query)
                    .sort({ requestDate: -1 }) 
                    .toArray();

                res.send(requests);
            } catch (error) {
                console.error("Error fetching donation requests:", error);
                res.status(500).send({ message: "Failed to fetch donation requests from database." });
            }
        });
        // **. সমস্ত ডোনেশন রিকোয়েস্ট লোড করা (Public, Filterable)
        // ফ্রন্টএন্ডে কল: /all-request 
        app.get('/all-request', async (req, res) => {
            const { status } = req.query; 
            const query = {};

            if (status === 'pending') {
                query.donationStatus = 'pending'; 
            }
            
            try {
                const requests = await donationCollections.find(query)
                    .sort({ requestDate: -1 }) 
                    .toArray();

                res.send(requests);
            } catch (error) {
                console.error("Error fetching donation requests:", error);
                res.status(500).send({ message: "Failed to fetch donation requests from database." });
            }
        });

        // ৬. নির্দিষ্ট রিকোয়েস্টের বিস্তারিত লোড করা (Private)
        // ফ্রন্টএন্ডে কল: /donation-requests/:id 
        app.get('/donation-requests/:id', verifyJWT, async (req, res) => {
            try {
                const id = req.params.id;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: 'Invalid ID format' });
                }
                
                const filter = { _id: new ObjectId(id) };
                const request = await donationCollections.findOne(filter);

                if (!request) {
                    return res.status(404).send({ message: 'Donation request not found.' });
                }
                
                res.send(request);

            } catch (error) {
                console.error("Get Single Request Error:", error);
                res.status(500).send({ message: 'Internal server error while fetching request details' });
            }
        });

        // ৭. ডোনেশন কনফার্ম করে স্ট্যাটাস পরিবর্তন করা (Private)
        // ফ্রন্টএন্ডে কল: PATCH /donation-requests/status/:id
        app.patch('/donation-requests/status/:id', verifyJWT, async (req, res) => {
            try {
                const id = req.params.id;
                const { status, donor } = req.body; 
                const donorEmailFromToken = req.decoded.email;
                
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: 'Invalid ID format' });
                }
                
                const filter = { _id: new ObjectId(id) };
                const request = await donationCollections.findOne(filter);

                if (!request) {
                    return res.status(404).send({ message: 'Donation request not found.' });
                }
                
                // শুধুমাত্র 'pending' থেকে 'inprogress' ট্রানজিশন অনুমোদন
                if (request.donationStatus !== 'pending' || status !== 'inprogress') {
                    return res.status(400).send({ message: 'Invalid status transition. Only Pending -> Inprogress is allowed here.' });
                }

                // ডোনারের তথ্য চেক
                if (!donor || donor.email !== donorEmailFromToken) {
                    return res.status(403).send({ message: 'Forbidden: Donor email mismatch.' });
                }
                
                const updateFields = { 
                    donationStatus: 'inprogress',
                    donorName: donor.name, 
                    donorEmail: donor.email, 
                    donornumber: donor.number, 
                };

                const result = await donationCollections.updateOne(filter, { $set: updateFields });
                
                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: 'Request matched but not updated.' });
                }
                
                res.send({ success: true, message: `Status updated to ${updateFields.donationStatus}`, modifiedCount: result.modifiedCount });

            } catch (error) {
                console.error("Update Status Error:", error);
                res.status(500).send({ message: 'Internal server error during status update' });
            }
        });
// ১. Admin Middleware (অবশ্যই verifyJWT এর পরে ব্যবহার করতে হবে)
const verifyAdmin = async (req, res, next) => {
    const email = req.decoded.email;
    const query = { email: email };
    const user = await userCollections.findOne(query);
    if (user?.role !== 'admin') {
        return res.status(403).send({ error: true, message: 'Forbidden: Admin only!' });
    }
    next();
};

// ২. সব ইউজারদের দেখার API (Admin Only)
app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
    const result = await userCollections.find().toArray();
    res.send(result);
});

// ৩. ইউজারের রোল পরিবর্তন (Donor থেকে Admin)
app.patch('/users/admin/:id', verifyJWT, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { role: 'admin' } };
    const result = await userCollections.updateOne(filter, updateDoc);
    res.send(result);
});

// ৪. ইউজারকে ব্লক/আনব্লক করার API
app.patch('/users/status/:id', verifyJWT, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    const { status } = req.body; // status: 'active' or 'blocked'
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { status: status } };
    const result = await userCollections.updateOne(filter, updateDoc);
    res.send(result); 
});
//admin-status
app.get('/admin-stats', verifyJWT, verifyAdmin, async (req, res) => {
    const totalUsers = await userCollections.estimatedDocumentCount();
    const totalRequests = await donationCollections.estimatedDocumentCount();
    
    // নির্দিষ্ট কিছু ডাটা ফিল্টার করা (যেমন: কয়টি রিকোয়েস্ট 'pending')
    const pendingRequests = await donationCollections.countDocuments({ donationStatus: 'pending' });
    
    // আপনি চাইলে আরও ডাটা যোগ করতে পারেন
    const totalDonors = await userCollections.countDocuments({ role: 'donor' });

    res.send({
        totalUsers,
        totalRequests,
        pendingRequests,
        totalDonors
    });
}); 
//all users
app.get('/all-donation-requests', verifyJWT, verifyAdmin, async (req, res) => {
    const result = await donationCollections.find().toArray();
    res.send(result);
});
// রক্তদাতা খোঁজার এপিআই
app.get('/search-donors', async (req, res) => {
    const { bloodGroup, district, upazila } = req.query;
    
    // কোয়েরি অবজেক্ট তৈরি
    let query = { role: 'donor' }; // শুধুমাত্র ডোনারদের খুঁজবে

    if (bloodGroup) query.bloodGroup = bloodGroup;
    if (district) query.district = district;
    if (upazila) query.upazila = upazila;

    const result = await userCollections.find(query).toArray();
    res.send(result);
});
//donor-details
app.get('/donor-details/:id', async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await userCollections.findOne(query, {
        projection: { name: 1, email: 1, image: 1, bloodGroup: 1, district: 1, upazila: 1, phone: 1 } // শুধুমাত্র প্রয়োজনীয় তথ্য
    });
    res.send(result);
});
//edit-profile
app.patch('/user/update/:email', verifyJWT, async (req, res) => {
    const email = req.params.email;
    const updatedData = req.body;
    const filter = { email: email };
    const updatedDoc = {
        $set: {
            name: updatedData.name,
            phone: updatedData.phone,
            district: updatedData.district,
            upazila: updatedData.upazila,
            bloodGroup: updatedData.bloodGroup
        }
    };
    const result = await userCollections.updateOne(filter, updatedDoc);
    res.send(result);
});
//cheacking admin or not by email
// ইউজারের ইমেইল দিয়ে চেক করা সে অ্যাডমিন কি না
app.get('/users/admin/:email', async (req, res) => {
    const email = req.params.email;
    
    // ঐচ্ছিক: টোকেনের ইমেইল আর রিকোয়েস্টের ইমেইল মিলছে কি না চেক করা (Security)
    // if (email !== req.decoded.email) {
    //     return res.status(403).send({ message: 'forbidden access' })
    // }

    const query = { email: email };
    const user = await userCollections.findOne(query);
    
    let admin = false;
    if (user) {
        admin = user?.role === 'admin';
    }
    res.send({ admin });
});
// শুধুমাত্র 'published' স্ট্যাটাসের ব্লগগুলো দেখানোর জন্য
app.get('/blogs', async (req, res) => {
    const blogs = await blogCollections
      .find({ status: 'published' })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(blogs);
  });
//payment er jonno 

// --------------------- Stripe PaymentIntent ---------------------
app.post('/create-payment-intent', async (req, res) => {
  const { price } = req.body;
  const amount = Math.round(price * 100);

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'bdt',
      payment_method_types: ['card'],
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: 'Stripe PaymentIntent creation failed' });
  }
});


// --------------------- Save payment ---------------------
app.post('/payments', async (req, res) => {
  try {
    const payment = req.body;

    // Validate minimal fields
    if (!payment.amount || !payment.name || !payment.method) {
      return res.status(400).send({ error: 'Invalid payment data. amount, name, method required.' });
    }

    // For manual payment, generate a pseudo transactionId if not provided
    if (!payment.transactionId) {
      payment.transactionId = `${payment.method}-${Date.now()}`;
    }

    payment.date = new Date();

    const result = await paymentCollection.insertOne(payment);
    res.send(result);
  } catch (err) {
    console.error("Save payment error:", err);
    res.status(500).send({ error: 'Internal server error' });
  }
});


// --------------------- Get all payments ---------------------
app.get('/payments', async (req, res) => {
  const result = await paymentCollection.find().sort({ date: -1 }).toArray();
  res.send(result);
});


// --------------------- Total funds ---------------------
app.get('/payments/total', async (req, res) => {
  const result = await paymentCollection.aggregate([
    { $group: { _id: null, total: { $sum: '$amount' } } },
  ]).toArray();
  res.send({ total: result[0]?.total || 0 });
});

        //my-request data api
        // ১. শুধুমাত্র নিজের করা রিকোয়েস্টগুলো দেখার API
app.get('/my-requests/:email', verifyJWT, async (req, res) => {
    const email = req.params.email;
    if (req.decoded.email !== email) {
        return res.status(403).send({ message: 'Forbidden access' });
    }
    const query = { requesterEmail: email };
    const result = await donationCollections.find(query).sort({ createdAt: -1 }).toArray();
    res.send(result);
});

// ২. রিকোয়েস্ট ডিলিট করার API
app.delete('/donation-requests/:id', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await donationCollections.deleteOne(query);
    res.send(result);
});

// ৩. স্ট্যাটাস পরিবর্তন করার API (Done/Canceled করার জন্য)
app.patch('/donation-requests/update-status/:id', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const { status } = req.body;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: { donationStatus: status }
    };
    const result = await donationCollections.updateOne(filter, updateDoc);
    res.send(result);
});  
// রিকোয়েস্ট আপডেট করার API
app.patch('/update-request/:id', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const updatedData = req.body;
    const query = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: updatedData
    };
    const result = await donationCollections.updateOne(query, updateDoc);
    res.send(result);
});

// koto gula donation confirm kora hoise tar api
app.get('/my-donations/:email', verifyJWT, async (req, res) => {
    const email = req.params.email;
    if (req.decoded.email !== email) {
        return res.status(403).send({ message: 'Forbidden access' });
    }
   
    const query = { donorEmail: email };
    const result = await donationCollections.find(query).toArray();
    res.send(result);
});

 // ইউজারের প্রোফাইল তথ্য আনা
app.get('/user/:email', verifyJWT, async (req, res) => {
    const email = req.params.email;
    const query = { email: email };
    const user = await userCollections.findOne(query);
    res.send(user);
});

        // ----------------------------------------------------
        // C. PUBLIC DATA APIs (অন্যান্য)
        // ----------------------------------------------------
        
        // ৮. জেলা ও উপজেলা ডেটা API: /public/districts (Public)
        app.get('/public/districts', async (req, res) => {
            try {
                if (districtsData.length > 0) {
                     return res.send(districtsData);
                }
                res.status(404).send({ message: 'Administrative data not available.' });
            } catch (error) {
                console.error("Districts Data Error:", error);
                res.status(500).send({ message: 'Internal server error while fetching administrative data' });
            }
        }); 
        //9: নতুন রুট: ডোনার সার্চ করার API (Public)
// ফ্রন্টএন্ড কল: /users/search?bloodGroup=A+&district=Dhaka
    app.get('/users/search', async (req, res) => {
    try {
        const { bloodGroup, district } = req.query; // ইউআরএল থেকে সার্চের মানগুলো নেওয়া হলো
        
        const query = {};
        
        // যদি ব্লাড গ্রুপ দেওয়া থাকে, তবে সেটা কুয়েরিতে যোগ করো
        if (bloodGroup) {
            query.bloodGroup = bloodGroup;
        }
        
        // যদি জেলা দেওয়া থাকে, তবে সেটা কুয়েরিতে যোগ করো
        if (district) {
            query.district = district;
        }

        // শুধুমাত্র যাদের রোল 'donor' এবং স্ট্যাটাস 'active', তাদের খুঁজবো
        query.role = 'donor';
        query.status = 'active';

        const donors = await userCollections.find(query).toArray();
        
        // রেজাল্ট সার্ভার থেকে পাঠানো হচ্ছে
        res.send(donors);

    } catch (error) {
        console.error("Search API Error:", error);
        res.status(500).send({ message: "Searching donors failed!" });
    } 
    
}); 
// ১০. নতুন ডোনেশন রিকোয়েস্ট তৈরি করা (Private)
app.post('/donation-requests', async (req, res) => {
    try {
        const requestData = req.body;
        
        // ডিফল্ট স্ট্যাটাস 'pending' যোগ করা
        const newRequest = {
            ...requestData,
            donationStatus: 'pending',
            createdAt: new Date()
        };

        const result = await donationCollections.insertOne(newRequest);
        res.send(result);
    } catch (error) {
        console.error("Error creating donation request:", error);
        res.status(500).send({ message: "Failed to create request" });
    }
});


        // ----------------------------------------------------
        // PING & START
        // ----------------------------------------------------
        // await client.db("admin").command({ ping: 1 });
        console.log("🟢 Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send("🩸 Blood Donor Server is Running and Ready for Action! 🚀");
});


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});