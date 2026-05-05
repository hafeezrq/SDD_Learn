const express = require("express");
const app = express();
app.use(express.json());

const crypto = require("crypto");
const sessions = new Map(); // token → session data
const SESSION_TTL = 1000; // 1 second (short for testing)

const bcrypt = require("bcrypt");

const SALT_ROUNDS = 10;

function hashPassword(password) {
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

const users = new Map();

// seed users
users.set("user1@example.com", {
  email: "user1@example.com",
  passwordHash: hashPassword("password123"),
});

users.set("user2@example.com", {
  email: "user2@example.com",
  passwordHash: hashPassword("password456"),
});

users.set("user@example.com", {
  email: "user@example.com",
  passwordHash: hashPassword("correctpassword"),
});

function constantTimeCompare(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) return false;

  return crypto.timingSafeEqual(bufA, bufB);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

const DUMMY_HASH = hashPassword("dummy_password");

function isValidEmail(email) {
  return typeof email === "string" && /^\S+@\S+\.\S+$/.test(email);
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// User Login

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !isValidEmail(normalizeEmail(email)) ||
    password.length < 8
  ) {
    return res.status(400).json({
      error: "invalid_input",
    });
  }

  const validEmail = normalizeEmail(email);
  const user = users.get(validEmail);
  let passwordValid = false;

  if (user) {
    passwordValid = await verifyPassword(password, user.passwordHash);
  } else {
    // still do dummy compare for timing safety
    await verifyPassword(password, DUMMY_HASH);
  }

  if (user && passwordValid) {
    const token = generateSessionToken();

    sessions.set(token, {
      email: user.email,
      expiresAt: Date.now() + SESSION_TTL,
    });

    return res.status(200).json({
      session_token: token,
    });
  }

  return res.status(401).json({
    error: "invalid_credentials",
  });
});

// User's Profile

app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "missing_token" });
  }

  const session = sessions.get(token);

  if (!session) {
    return res.status(401).json({ error: "invalid_token" });
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(token); // cleanup
    return res.status(401).json({ error: "session_expired" });
  }

  return res.status(200).json({
    email: session.email,
  });
});

// User Logout

app.post("/logout", (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "missing_token" });
  }

  const session = sessions.get(token);

  if (!session) {
    return res.status(401).json({ error: "invalid_token" });
  }

  // ✅ invalidate session
  sessions.delete(token);

  return res.status(200).json({ message: "logged_out" });
});

// User Registration

app.post("/register", async (req, res) => {
  let { email, password } = req.body;

  // ✅ normalize
  if (typeof email === "string") {
    email = email.trim().toLowerCase();
  }

  // ✅ validate
  if (
    !isValidEmail(email) ||
    typeof password !== "string" ||
    password.length < 8
  ) {
    return res.status(400).json({
      error: "invalid_input",
    });
  }

  // ✅ check duplicate
  if (users.has(email)) {
    return res.status(409).json({
      error: "email_exists",
    });
  }

  // ✅ create user
  const passwordHash = hashPassword(password);

  users.set(email, {
    email,
    passwordHash,
  });

  return res.status(201).json({
    message: "user_created",
  });
});

module.exports = app;
