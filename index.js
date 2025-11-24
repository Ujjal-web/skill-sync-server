require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000' }));

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: false },
    providers: { type: Array, default: [] }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

function createAccessToken(user) {
    return jwt.sign(
        { sub: user._id.toString(), email: user.email, name: user.name },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
}

/* ---------------------------
   Register
   POST /auth/register
   --------------------------- */
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

        const existing = await User.findOne({ email });
        if (existing) return res.status(409).json({ message: 'User already exists' });

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await User.create({ email, name, passwordHash });

        return res.status(201).json({ user: { id: user._id, email: user.email, name: user.name } });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

/* ---------------------------
   Login
   POST /auth/login
   --------------------------- */
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

        const user = await User.findOne({ email });
        if (!user || !user.passwordHash) return res.status(401).json({ message: 'Invalid credentials' });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

        const accessToken = createAccessToken(user);
        return res.json({ user: { id: user._id, email: user.email, name: user.name }, accessToken });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

/* ---------------------------
   NEW: OAuth handler
   POST /auth/oauth
   Body: { provider, providerId, email, name, picture }
   Upserts a user and returns { user, accessToken }
   --------------------------- */
app.post('/auth/oauth', async (req, res) => {
    try {
        const { provider, providerId, email, name, picture } = req.body;
        if (!provider || !providerId || !email) return res.status(400).json({ message: 'Missing provider data' });

        // 1) Try to find by providerId
        let user = await User.findOne({ 'providers.provider': provider, 'providers.providerId': providerId });

        // 2) fallback: find by email (user registered earlier)
        if (!user) {
            user = await User.findOne({ email });
        }

        // 3) create user if none
        if (!user) {
            user = new User({
                email,
                name,
                passwordHash: '',
                providers: [{ provider, providerId, profile: { name, picture } }]
            });
            await user.save();
        } else {
            // link provider if not already linked
            const linked = (user.providers || []).some(p => p.provider === provider && p.providerId === providerId);
            if (!linked) {
                user.providers = user.providers || [];
                user.providers.push({ provider, providerId, profile: { name, picture } });
                await user.save();
            }
        }

        const accessToken = createAccessToken(user);
        return res.json({ user: { id: user._id, email: user.email, name: user.name }, accessToken });
    } catch (err) {
        console.error('OAuth error:', err);
        // handle duplicate key (email)
        if (err && err.code === 11000) {
            return res.status(409).json({ message: 'Email already exists' });
        }
        return res.status(500).json({ message: 'Server error' });
    }
});

function verifyToken(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ message: 'Missing token' });
    const token = header.split(' ')[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
}
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: `Hello ${req.user.name || req.user.email}, this is protected.` });
});

/* ---------------------------
   Start server & connect MongoDB
   --------------------------- */
async function start() {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
        console.error('Missing MONGO_URI in .env');
        process.exit(1);
    }
    try {
        await mongoose.connect(mongoUri);
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    }

    const PORT = process.env.PORT || 4000;
    app.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));
}
start();