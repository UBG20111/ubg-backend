const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const allowedStatuses = ["Opportunities", "Bidding", "Submitted", "Won", "Lost"];

app.use(cors({ origin: "*" }));
app.use(express.json());

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error("DATABASE_URL is missing. Add it in Render Environment Variables.");
  process.exit(1);
}

const jwtSecret = process.env.JWT_SECRET || "temporary-ubg-login-secret-change-in-render";

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: {
    rejectUnauthorized: false
  }
});

function cleanText(value) {
  if (value === undefined || value === null) return null;
  const cleaned = String(value).trim();
  return cleaned.length ? cleaned : null;
}

function normalizeEmail(value) {
  const email = cleanText(value);
  return email ? email.toLowerCase() : null;
}

function cleanStatus(value) {
  const status = cleanText(value) || "Opportunities";
  return allowedStatuses.includes(status) ? status : "Opportunities";
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    jwtSecret,
    {
      expiresIn: "12h"
    }
  );
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: "Login required." });
    }

    const decoded = jwt.verify(token, jwtSecret);

    const result = await pool.query(
      `
      SELECT id, email, role, is_active
      FROM app_users
      WHERE id = $1
      LIMIT 1
      `,
      [decoded.id]
    );

    if (!result.rows.length || !result.rows[0].is_active) {
      return res.status(401).json({ error: "User not authorized." });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired login." });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }

  next();
}

app.get("/", (req, res) => {
  res.send("UBG Backend Running");
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    const userCountResult = await pool.query("SELECT COUNT(*)::int AS count FROM app_users");
    const userCount = userCountResult.rows[0].count;

    res.json({
      ok: true,
      service: "ubg-backend",
      database: "connected",
      login_ready: userCount > 0,
      users: userCount
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      service: "ubg-backend",
      database: "error",
      error: error.message
    });
  }
});

app.post("/auth/setup", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = cleanText(req.body.password);

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters."
      });
    }

    const countResult = await pool.query("SELECT COUNT(*)::int AS count FROM app_users");
    const userCount = countResult.rows[0].count;

    if (userCount > 0) {
      return res.status(409).json({
        error: "Setup is already complete. Please login."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO app_users
        (email, password_hash, role, is_active, updated_at)
      VALUES
        ($1, $2, 'admin', true, now())
      RETURNING id, email, role, is_active, created_at
      `,
      [email, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken(user);

    res.json({
      user,
      token
    });
  } catch (error) {
    console.error("POST /auth/setup error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = cleanText(req.body.password);

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const result = await pool.query(
      `
      SELECT id, email, password_hash, role, is_active
      FROM app_users
      WHERE email = $1
      LIMIT 1
      `,
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const userRecord = result.rows[0];

    if (!userRecord.is_active) {
      return res.status(403).json({
        error: "This user is inactive."
      });
    }

    const passwordMatches = await bcrypt.compare(password, userRecord.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = {
      id: userRecord.id,
      email: userRecord.email,
      role: userRecord.role,
      is_active: userRecord.is_active
    };

    const token = createToken(user);

    res.json({
      user,
      token
    });
  } catch (error) {
    console.error("POST /auth/login error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/auth/me", requireAuth, async (req, res) => {
  res.json({
    user: req.user
  });
});

app.post("/auth/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = cleanText(req.body.password);
    const role = cleanText(req.body.role) === "admin" ? "admin" : "user";

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO app_users
        (email, password_hash, role, is_active, updated_at)
      VALUES
        ($1, $2, $3, true, now())
      RETURNING id, email, role, is_active, created_at
      `,
      [email, passwordHash, role]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("POST /auth/users error:", error);

    if (String(error.message).includes("duplicate key")) {
      return res.status(409).json({
        error: "A user with that email already exists."
      });
    }

    res.status(500).json({ error: error.message });
  }
});

app.get("/auth/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, email, role, is_active, created_at, updated_at
      FROM app_users
      ORDER BY created_at DESC
      `
    );

    res.json(result.rows);
  } catch (error) {
    console.error("GET /auth/users error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/bids", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        project_name,
        company,
        status,
        due_date,
        source,
        estimator,
        notes,
        created_by_user_id,
        created_at,
        updated_at
      FROM bid_opportunities
      ORDER BY
        CASE status
          WHEN 'Opportunities' THEN 1
          WHEN 'Bidding' THEN 2
          WHEN 'Submitted' THEN 3
          WHEN 'Won' THEN 4
          WHEN 'Lost' THEN 5
          ELSE 6
        END,
        due_date ASC NULLS LAST,
        created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("GET /bids error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/bids", requireAuth, async (req, res) => {
  try {
    const project_name = cleanText(req.body.project_name);
    const company = cleanText(req.body.company);
    const status = cleanStatus(req.body.status);
    const due_date = cleanText(req.body.due_date);
    const source = cleanText(req.body.source);
    const estimator = cleanText(req.body.estimator);
    const notes = cleanText(req.body.notes);

    if (!project_name || !company) {
      return res.status(400).json({
        error: "Project Name and Company are required."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO bid_opportunities
        (project_name, company, status, due_date, source, estimator, notes, created_by_user_id, updated_at)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, now())
      RETURNING *
      `,
      [project_name, company, status, due_date, source, estimator, notes, req.user.id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("POST /bids error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/bids/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const project_name = cleanText(req.body.project_name);
    const company = cleanText(req.body.company);
    const status = cleanStatus(req.body.status);
    const due_date = cleanText(req.body.due_date);
    const source = cleanText(req.body.source);
    const estimator = cleanText(req.body.estimator);
    const notes = cleanText(req.body.notes);

    if (!project_name || !company) {
      return res.status(400).json({
        error: "Project Name and Company are required."
      });
    }

    const result = await pool.query(
      `
      UPDATE bid_opportunities
      SET
        project_name = $1,
        company = $2,
        status = $3,
        due_date = $4,
        source = $5,
        estimator = $6,
        notes = $7,
        updated_at = now()
      WHERE id = $8
      RETURNING *
      `,
      [project_name, company, status, due_date, source, estimator, notes, id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Bid not found." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("PUT /bids/:id error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/bids/:id/status", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const status = cleanStatus(req.body.status);

    const result = await pool.query(
      `
      UPDATE bid_opportunities
      SET status = $1, updated_at = now()
      WHERE id = $2
      RETURNING *
      `,
      [status, id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Bid not found." });
    }

    await pool.query(
      `
      INSERT INTO bid_intents (bid_id, user_id, intent)
      VALUES ($1, $2, $3)
      `,
      [id, req.user.id, status]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("POST /bids/:id/status error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/bids/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const result = await pool.query(
      `
      DELETE FROM bid_opportunities
      WHERE id = $1
      RETURNING *
      `,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Bid not found." });
    }

    res.json({
      deleted: true,
      bid: result.rows[0]
    });
  } catch (error) {
    console.error("DELETE /bids/:id error:", error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`UBG backend running on port ${PORT}`);
});
