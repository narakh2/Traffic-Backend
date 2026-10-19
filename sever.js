require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error("Please set JWT_SECRET in your .env file (at least 32 characters).");
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "100kb" }));

const db = new Database(process.env.DATABASE_FILE || "./trafficpilot.sqlite");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  credits INTEGER NOT NULL DEFAULT 20,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  service_type TEXT NOT NULL,
  target_url TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  base_reward INTEGER NOT NULL,
  country_tier TEXT NOT NULL,
  reward INTEGER NOT NULL,
  completions INTEGER NOT NULL,
  remaining INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
  worker_id INTEGER NOT NULL REFERENCES users(id),
  proof_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(campaign_id, worker_id)
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  amount_usdt REAL NOT NULL,
  wallet_address TEXT NOT NULL,
  tx_hash TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount INTEGER NOT NULL,
  note TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const services = [
  "Follow",
  "Share",
  "Comment",
  "React post",
  "Watch Video",
  "Subscribe",
  "Visit Website",
  "Read Article"
];

const rewards = {
  5: 3,
  10: 5,
  30: 10,
  60: 15,
  120: 20,
  180: 25
};

const tiers = {
  global: 0,
  tier1: 15,
  tier2: 10,
  tier3: 5
};

function fail(res, status, message) {
  return res.status(status).json({ error: message });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return fail(res, 401, "Please sign in.");
  }

  try {
    const data = jwt.verify(token, SECRET);
    const user = db.prepare(
      "SELECT id, username, email, credits, role FROM users WHERE id = ?"
    ).get(data.id);

    if (!user) return fail(res, 401, "User not found.");

    req.user = user;
    next();
  } catch {
    return fail(res, 401, "Invalid or expired login. Please sign in again.");
  }
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return fail(res, 403, "Administrator access required.");
  }
  next();
}

function addLedger(userId, amount, note) {
  db.prepare(
    "INSERT INTO ledger(user_id, amount, note) VALUES (?, ?, ?)"
  ).run(userId, amount, note);
}

function validUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

// Status
app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "TrafficPilot Backend",
    status: "online",
    payment: "USDT on TON only",
    adsgram: "Not integrated yet"
  });
});

app.get("/health", (req, res) => {
  db.prepare("SELECT 1").get();
  res.json({ success: true, database: "connected" });
});

// Public configuration
app.get("/api/config", (req, res) => {
  res.json({
    welcomeCredits: 20,
    services,
    rewards,
    countryTiers: tiers,
    minimumCompletions: 10,
    maximumCompletions: 5000,
    paymentMethods: ["USDT (TON)"],
    adsgram: false
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (username.length < 2) {
      return fail(res, 400, "Username must have at least 2 characters.");
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return fail(res, 400, "Enter a valid email address.");
    }

    if (password.length < 10 || password.length > 128) {
      return fail(res, 400, "Password must be 10 to 128 characters.");
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users(username, email, password_hash, credits)
      VALUES (?, ?, ?, 20)
    `).run(username, email, hash);

    addLedger(Number(result.lastInsertRowid), 20, "Welcome bonus");

    const user = {
      id: Number(result.lastInsertRowid),
      username,
      email,
      credits: 20,
      role: "user"
    };

    const token = jwt.sign({ id: user.id }, SECRET, {
      expiresIn: "7d"
    });

    res.status(201).json({ token, user });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return fail(res, 409, "Email is already registered.");
    }

    console.error(error);
    fail(res, 500, "Registration failed.");
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const row = db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).get(email);

    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return fail(res, 401, "Incorrect email or password.");
    }

    const token = jwt.sign({ id: row.id }, SECRET, {
      expiresIn: "7d"
    });

    res.json({
      token,
      user: {
        id: row.id,
        username: row.username,
        email: row.email,
        credits: row.credits,
        role: row.role
      }
    });
  } catch (error) {
    console.error(error);
    fail(res, 500, "Login failed.");
  }
});

// Current user and credit ledger
app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/ledger", auth, (req, res) => {
  const entries = db.prepare(`
    SELECT * FROM ledger
    WHERE user_id = ?
    ORDER BY id DESC LIMIT 100
  `).all(req.user.id);

  res.json({ entries });
});

// Create campaign
app.post("/api/campaigns", auth, (req, res) => {
  try {
    const title = String(req.body.title || "").trim();
    const service = String(req.body.serviceType || "");
    const url = String(req.body.targetUrl || "").trim();
    const duration = Number(req.body.durationSeconds);
    const tier = String(req.body.countryTier || "global");
    const count = Number(req.body.completions);

    if (title.length < 3) {
      return fail(res, 400, "Campaign title is too short.");
    }

    if (!services.includes(service)) {
      return fail(res, 400, "Invalid service type.");
    }

    if (!validUrl(url)) {
      return fail(res, 400, "Enter a valid website URL.");
    }

    if (!rewards[duration]) {
      return fail(res, 400, "Invalid task duration.");
    }

    if (!(tier in tiers)) {
      return fail(res, 400, "Invalid country tier.");
    }

    if (!Number.isInteger(count) || count < 10 || count > 5000) {
      return fail(res, 400, "Completions must be 10 to 5000.");
    }

    const baseReward = rewards[duration];
    const reward = Math.ceil(baseReward * (100 + tiers[tier]) / 100);
    const budget = reward * count;

    const create = db.transaction(() => {
      const user = db.prepare(
        "SELECT credits FROM users WHERE id = ?"
      ).get(req.user.id);

      if (user.credits < budget) {
        throw new Error("INSUFFICIENT_CREDITS");
      }

      db.prepare(
        "UPDATE users SET credits = credits - ? WHERE id = ?"
      ).run(budget, req.user.id);

      addLedger(req.user.id, -budget, "Campaign budget reserved");

      return db.prepare(`
        INSERT INTO campaigns(
          user_id, title, service_type, target_url,
          duration_seconds, base_reward, country_tier,
          reward, completions, remaining
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id, title, service, url, duration,
        baseReward, tier, reward, count, count
      );
    });

    const result = create();

    res.status(201).json({
      success: true,
      campaignId: Number(result.lastInsertRowid),
      rewardPerCompletion: reward,
      totalBudget: budget
    });
  } catch (error) {
    if (error.message === "INSUFFICIENT_CREDITS") {
      return fail(res, 400, "You do not have enough credits.");
    }

    console.error(error);
    fail(res, 500, "Could not create campaign.");
  }
});

// List your campaigns
app.get("/api/campaigns", auth, (req, res) => {
  const campaigns = db.prepare(`
    SELECT * FROM campaigns
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.user.id);

  res.json({ campaigns });
});

// Browse available tasks
app.get("/api/tasks", auth, (req, res) => {
  const tasks = db.prepare(`
    SELECT c.*
    FROM campaigns c
    WHERE c.status = 'active'
      AND c.remaining > 0
      AND c.user_id != ?
      AND NOT EXISTS (
        SELECT 1 FROM submissions s
        WHERE s.campaign_id = c.id
          AND s.worker_id = ?
      )
    ORDER BY c.id DESC
    LIMIT 100
  `).all(req.user.id, req.user.id);

  res.json({ tasks });
});

// Submit proof for manual review
app.post("/api/tasks/:id/submit", auth, (req, res) => {
  try {
    const campaignId = Number(req.params.id);
    const proofUrl = String(req.body.proofUrl || "").trim();

    if (!validUrl(proofUrl)) {
      return fail(res, 400, "Enter a valid proof URL.");
    }

    const campaign = db.prepare(`
      SELECT * FROM campaigns
      WHERE id = ? AND status = 'active' AND remaining > 0
    `).get(campaignId);

    if (!campaign) {
      return fail(res, 404, "Campaign is not available.");
    }

    if (campaign.user_id === req.user.id) {
      return fail(res, 400, "You cannot complete your own campaign.");
    }

    const result = db.prepare(`
      INSERT INTO submissions(campaign_id, worker_id, proof_url)
      VALUES (?, ?, ?)
    `).run(campaignId, req.user.id, proofUrl);

    res.status(201).json({
      success: true,
      submissionId: Number(result.lastInsertRowid),
      status: "pending"
    });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return fail(res, 409, "You already submitted this task.");
    }

    console.error(error);
    fail(res, 500, "Could not submit task.");
  }
});

// Deposit request: USDT on TON only
app.post("/api/payments/deposit", auth, (req, res) => {
  const amount = Number(req.body.amountUsdt);
  const wallet = String(req.body.walletAddress || "").trim();
  const txHash = String(req.body.txHash || "").trim();

  if (!Number.isFinite(amount) || amount <= 0) {
    return fail(res, 400, "Enter a valid USDT amount.");
  }

  if (wallet.length < 20) {
    return fail(res, 400, "Enter the sender wallet address on TON.");
  }

  const result = db.prepare(`
    INSERT INTO payments(user_id, kind, amount_usdt, wallet_address, tx_hash)
    VALUES (?, 'deposit', ?, ?, ?)
  `).run(req.user.id, amount, wallet, txHash);

  res.status(201).json({
    success: true,
    requestId: Number(result.lastInsertRowid),
    status: "pending",
    message: "Manual payment verification is required."
  });
});

// Withdraw request: USDT on TON only
// Demo conversion: 10,000 credits = 1 USDT.
app.post("/api/payments/withdraw", auth, (req, res) => {
  const amount = Number(req.body.amountUsdt);
  const wallet = String(req.body.walletAddress || "").trim();

  if (!Number.isFinite(amount) || amount < 1) {
    return fail(res, 400, "Minimum withdrawal is 1 USDT.");
  }

  if (wallet.length < 20) {
    return fail(res, 400, "Enter a valid TON wallet address.");
  }

  const credits = Math.ceil(amount * 10000);

  const create = db.transaction(() => {
    const user = db.prepare(
      "SELECT credits FROM users WHERE id = ?"
    ).get(req.user.id);

    if (user.credits < credits) {
      throw new Error("INSUFFICIENT_CREDITS");
    }

    db.prepare(
      "UPDATE users SET credits = credits - ? WHERE id = ?"
    ).run(credits, req.user.id);

    addLedger(req.user.id, -credits, "Withdrawal credits held");

    return db.prepare(`
      INSERT INTO payments(user_id, kind, amount_usdt, wallet_address)
      VALUES (?, 'withdraw', ?, ?)
    `).run(req.user.id, amount, wallet);
  });

  try {
    const result = create();

    res.status(201).json({
      success: true,
      requestId: Number(result.lastInsertRowid),
      status: "pending",
      message: "Withdrawal requires manual review; no crypto is sent automatically."
    });
  } catch (error) {
    if (error.message === "INSUFFICIENT_CREDITS") {
      return fail(res, 400, "Insufficient credits.");
    }

    console.error(error);
    fail(res, 500, "Could not create withdrawal request.");
  }
});

// Payment request history
app.get("/api/payments/mine", auth, (req, res) => {
  const requests = db.prepare(`
    SELECT * FROM payments
    WHERE user_id = ?
    ORDER BY id DESC LIMIT 100
  `).all(req.user.id);

  res.json({ requests });
});

// Administrator: review submitted tasks
app.get("/api/admin/submissions", auth, admin, (req, res) => {
  const submissions = db.prepare(`
    SELECT * FROM submissions
    WHERE status = 'pending'
    ORDER BY id ASC LIMIT 200
  `).all();

  res.json({ submissions });
});

app.post("/api/admin/submissions/:id/review", auth, admin, (req, res) => {
  const id = Number(req.params.id);
  const decision = String(req.body.decision || "");

  if (!["approve", "reject"].includes(decision)) {
    return fail(res, 400, "Decision must be approve or reject.");
  }

  try {
    const review = db.transaction(() => {
      const submission = db.prepare(`
        SELECT s.*, c.reward, c.remaining, c.id AS cid
        FROM submissions s
        JOIN campaigns c ON c.id = s.campaign_id
        WHERE s.id = ? AND s.status = 'pending'
      `).get(id);

      if (!submission) throw new Error("NOT_FOUND");

      if (decision === "approve") {
        if (submission.remaining < 1) {
          throw new Error("NO_COMPLETIONS");
        }

        db.prepare(
          "UPDATE users SET credits = credits + ? WHERE id = ?"
        ).run(submission.reward, submission.worker_id);

        addLedger(
          submission.worker_id,
          submission.reward,
          "Approved task reward"
        );

        db.prepare(
          "UPDATE campaigns SET remaining = remaining - 1 WHERE id = ?"
        ).run(submission.cid);
      }

      db.prepare(
        "UPDATE submissions SET status = ? WHERE id = ?"
      ).run(decision === "approve" ? "approved" : "rejected", id);
    });

    review();
    res.json({ success: true, status: decision });
  } catch (error) {
    if (error.message === "NOT_FOUND") {
      return fail(res, 404, "Pending submission not found.");
    }

    if (error.message === "NO_COMPLETIONS") {
      return fail(res, 400, "No completions remain.");
    }

    console.error(error);
    fail(res, 500, "Could not review submission.");
  }
});

// Error handling
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

app.listen(PORT, () => {
  console.log(`TrafficPilot backend running on port ${PORT}`);
});
