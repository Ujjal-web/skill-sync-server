require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    name: { type: String },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true }
}, { timestamps: true });


function createAccessToken(user) {
    return jwt.sign({ sub: user._id.toString(), email: user.email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

// Register
router.post('/register', async (req, res) => {
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

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

        const accessToken = createAccessToken(user);
        return res.json({ user: { id: user._id, email: user.email, name: user.name }, accessToken });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});


function verifyToken(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing or invalid Authorization header' });
    }
    const token = header.split(' ')[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
}



const app = express();
app.use(express.json());

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Connect to MongoDB
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

    // // Routes
    // app.use('/auth', authRoutes);

    // protected route
    app.get('/protected', verifyToken, (req, res) => {
        res.json({ message: ` ${req.user.name}, this is protected.` });
    });

    const port = process.env.PORT || 4000;
    app.listen(port, () => {
        console.log(`Backend running on http://localhost:${port}`);
    });
}

start();
