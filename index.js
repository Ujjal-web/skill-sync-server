const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));

const USERS = [
    { id: 1, email: "test@example.com", password: "123456" }
];

app.post("/auth/login", (req, res) => {
    const { email, password } = req.body;

    const user = USERS.find(u => u.email === email && u.password === password);

    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    return res.json({
        id: user.id,
        email: user.email
    });
});

app.listen(4000, () => console.log("Backend running on port 4000"));