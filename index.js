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

        // 2) fallback: find by email 
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
const SkillSchema = new mongoose.Schema({
    title: { type: String, required: true },
    shortDescription: { type: String, required: true },
    fullDescription: { type: String, required: true },
    category: { type: String, required: true },
    price: { type: Number, required: true, default: 0 },
    imageUrl: { type: String, default: null },
    ownerId: { type: String, required: true }, // store owner user id from token
}, { timestamps: true });

const Skill = mongoose.models.Skill || mongoose.model('Skill', SkillSchema);

// Create a skill
app.post('/skills', verifyToken, async (req, res) => {
    try {
        const { title, shortDescription, fullDescription, category, price, imageUrl } = req.body;

        // Basic validation
        if (!title || !shortDescription || !fullDescription || !category) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        const ownerId = req.user?.sub;
        if (!ownerId) return res.status(401).json({ message: 'Invalid token payload' });

        const skill = await Skill.create({
            title,
            shortDescription,
            fullDescription,
            category,
            price: typeof price === 'number' ? price : parseFloat(price) || 0,
            imageUrl: imageUrl || null,
            ownerId
        });

        return res.status(201).json({ skill });
    } catch (err) {
        console.error('Create skill error:', err);
        return res.status(500).json({ message: 'Server error creating skill' });
    }
});

// List skills 
app.get('/skills', async (req, res) => {
    try {
        const skills = await Skill.find().sort({ createdAt: -1 }).limit(100);
        return res.json({ skills });
    } catch (err) {
        console.error('List skills error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
});

app.get('/skills/my', verifyToken, async (req, res) => {
    try {
        const ownerId = req.user.sub; // user id from token

        const skills = await Skill.find({ ownerId }).sort({ createdAt: -1 });

        return res.json({ skills });
    } catch (err) {
        console.error('My skills error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
});

app.get('/skills/:id', async (req, res) => {
    try {
        const skill = await Skill.findById(req.params.id);

        if (!skill) {
            return res.status(404).json({ message: 'Skill not found' });
        }

        return res.json(skill);
    } catch (err) {
        console.error('Get skill error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/skills/:id', verifyToken, async (req, res) => {
    try {
        const skill = await Skill.findById(req.params.id);

        if (!skill) return res.status(404).json({ message: 'Skill not found' });

        if (skill.ownerId !== req.user.sub) {
            return res.status(403).json({ message: 'Not allowed to delete this skill' });
        }

        await skill.deleteOne();

        return res.json({ message: 'Skill deleted' });
    } catch (err) {
        console.error('Delete error:', err);
        return res.status(500).json({ message: 'Server error' });
    }
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