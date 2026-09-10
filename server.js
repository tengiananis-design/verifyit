import express from "express";
import crypto from "crypto";
import pg from "pg";
import QRCode from "qrcode";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* -----------------------------
   DATABASE SETUP
----------------------------- */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      business_id INTEGER NOT NULL,
      brand TEXT NOT NULL,
      product_name TEXT NOT NULL,
      batch TEXT DEFAULT '',
      code TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'active',
      verification_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (business_id)
        REFERENCES businesses(id)
        ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS verifications (
      id SERIAL PRIMARY KEY,
      product_id INTEGER,
      code TEXT NOT NULL,
      result TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE SET NULL
    );
  `);

  console.log("VerifyIt PostgreSQL database ready.");
}

function now() {
  return new Date().toISOString();
}

/* -----------------------------
   HELPERS
----------------------------- */

async function makeCode() {
  let code;

  do {
    code = crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
      .match(/.{1,4}/g)
      .join("-");
  } while (
    (
      await pool.query(
        "SELECT 1 FROM products WHERE code = $1",
        [code]
      )
    ).rowCount
  );

  return code;
}

function tokenFor(business) {
  return jwt.sign(
    {
      id: business.id,
      email: business.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      throw new Error("Missing token");
    }

    req.business = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: "Please log in."
    });
  }
}

function publicProduct(product) {
  return {
    brand: product.brand,
    productName: product.product_name,
    batch: product.batch,
    code: product.code,
    status: product.status,
    verificationCount:
      Number(product.verification_count),
    createdAt: product.created_at
  };
}

/* -----------------------------
   EXPRESS
----------------------------- */

app.use(express.json({ limit: "50kb" }));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* -----------------------------
   HEALTH CHECK
----------------------------- */

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "VerifyIt",
      version: "1.3.0",
      database: "postgresql"
    });
  } catch {
    res.status(500).json({
      ok: false,
      error: "Database connection failed."
    });
  }
});

/* -----------------------------
   BUSINESS REGISTRATION
----------------------------- */

app.post("/api/register", async (req, res) => {
  const {
    name,
    email,
    password
  } = req.body || {};

  if (
    !name ||
    !email ||
    !password ||
    password.length < 8
  ) {
    return res.status(400).json({
      error:
        "Name, email and a password of at least 8 characters are required."
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO businesses
      (name, email, password_hash, created_at)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, email
      `,
      [
        String(name).trim(),
        String(email).trim().toLowerCase(),
        hash,
        now()
      ]
    );

    const business = result.rows[0];

    res.status(201).json({
      token: tokenFor(business),
      business
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error:
          "That email is already registered."
      });
    }

    console.error(error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

/* -----------------------------
   BUSINESS LOGIN
----------------------------- */

app.post("/api/login", async (req, res) => {
  const {
    email,
    password
  } = req.body || {};

  try {
    const result = await pool.query(
      `
      SELECT *
      FROM businesses
      WHERE email = $1
      `,
      [
        String(email || "")
          .trim()
          .toLowerCase()
      ]
    );

    const business = result.rows[0];

    if (
      !business ||
      !(await bcrypt.compare(
        String(password || ""),
        business.password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    res.json({
      token: tokenFor(business),
      business: {
        id: business.id,
        name: business.name,
        email: business.email
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});

/* -----------------------------
   CURRENT BUSINESS
----------------------------- */

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, email, created_at
      FROM businesses
      WHERE id = $1
      `,
      [req.business.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "Business not found."
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

/* -----------------------------
   CREATE PRODUCT
----------------------------- */

app.post(
  "/api/products",
  auth,
  async (req, res) => {
    const {
      brand,
      productName,
      batch
    } = req.body || {};

    if (!brand || !productName) {
      return res.status(400).json({
        error:
          "Brand and product name are required."
      });
    }

    try {
      const code = await makeCode();
      const createdAt = now();

      const result = await pool.query(
        `
        INSERT INTO products
        (
          business_id,
          brand,
          product_name,
          batch,
          code,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        `,
        [
          req.business.id,
          String(brand).trim(),
          String(productName).trim(),
          String(batch || "").trim(),
          code,
          createdAt
        ]
      );

      res.status(201).json(
        publicProduct(result.rows[0])
      );
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to register product."
      });
    }
  }
);

/* -----------------------------
   LIST PRODUCTS
----------------------------- */

app.get(
  "/api/products",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM products
        WHERE business_id = $1
        ORDER BY id DESC
        `,
        [req.business.id]
      );

      res.json(
        result.rows.map(publicProduct)
      );
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load products."
      });
    }
  }
);

/* -----------------------------
   DELETE PRODUCT
----------------------------- */

app.delete(
  "/api/products/:code",
  auth,
  async (req, res) => {
    const code = String(
      req.params.code || ""
    )
      .trim()
      .toUpperCase();

    try {
      const result = await pool.query(
        `
        DELETE FROM products
        WHERE code = $1
        AND business_id = $2
        RETURNING id
        `,
        [
          code,
          req.business.id
        ]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Product not found."
        });
      }

      res.json({
        ok: true,
        message: "Product deleted."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to delete product."
      });
    }
  }
);

/* -----------------------------
   CHANGE PRODUCT STATUS
----------------------------- */

app.patch(
  "/api/products/:code/status",
  auth,
  async (req, res) => {
    const status = req.body?.status;

    if (
      ![
        "active",
        "disabled",
        "recalled"
      ].includes(status)
    ) {
      return res.status(400).json({
        error: "Invalid status."
      });
    }

    try {
      const result = await pool.query(
        `
        UPDATE products
        SET status = $1
        WHERE code = $2
        AND business_id = $3
        `,
        [
          status,
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Product not found."
        });
      }

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update product."
      });
    }
  }
);

/* -----------------------------
   GENERATE QR CODE
----------------------------- */

app.get(
  "/api/products/:code/qr",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM products
        WHERE code = $1
        AND business_id = $2
        `,
        [
          req.params.code,
          req.business.id
        ]
      );

      const product = result.rows[0];

      if (!product) {
        return res.status(404).json({
          error: "Product not found."
        });
      }

      const base =
        process.env.PUBLIC_BASE_URL ||
        `${req.protocol}://${req.get("host")}`;

      const verifyUrl =
        `${base}/?verify=${encodeURIComponent(
          product.code
        )}#verify`;

      const data =
        await QRCode.toDataURL(
          verifyUrl,
          {
            margin: 2,
            width: 600
          }
        );

      res.json({
        url: verifyUrl,
        data
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to generate QR code."
      });
    }
  }
);

/* -----------------------------
   PUBLIC PRODUCT VERIFICATION
----------------------------- */

app.get(
  "/api/verify/:code",
  async (req, res) => {
    const code = String(
      req.params.code || ""
    )
      .trim()
      .toUpperCase();

    try {
      const result = await pool.query(
        `
        SELECT *
        FROM products
        WHERE code = $1
        `,
        [code]
      );

      const product = result.rows[0];

      /* Code doesn't exist */

      if (!product) {
        await pool.query(
          `
          INSERT INTO verifications
          (code, result, checked_at)
          VALUES ($1, $2, $3)
          `,
          [
            code,
            "not_verified",
            now()
          ]
        );

        return res.json({
          result: "not_verified",
          message:
            "This code is not registered in the VerifyIt database."
        });
      }

      /* Determine result */

      let verificationResult;

      if (product.status !== "active") {
        verificationResult = "warning";
      } else if (
        Number(product.verification_count) >= 5
      ) {
        verificationResult = "warning";
      } else {
        verificationResult = "authentic";
      }

      let message;

      if (product.status !== "active") {
        message =
          `This product record is marked ${product.status}.`;
      } else if (
        verificationResult === "warning"
      ) {
        message =
          "This code is registered, but it has unusually high verification activity. Check the item with the seller or manufacturer.";
      } else {
        message =
          "The code matches a registered product record.";
      }

      /* Increase verification count */

      await pool.query(
        `
        UPDATE products
        SET verification_count =
          verification_count + 1
        WHERE id = $1
        `,
        [product.id]
      );

      /* Record verification */

      await pool.query(
        `
        INSERT INTO verifications
        (
          product_id,
          code,
          result,
          checked_at
        )
        VALUES ($1, $2, $3, $4)
        `,
        [
          product.id,
          code,
          verificationResult,
          now()
        ]
      );

      const freshResult =
        await pool.query(
          `
          SELECT *
          FROM products
          WHERE id = $1
          `,
          [product.id]
        );

      res.json({
        result: verificationResult,
        product: publicProduct(
          freshResult.rows[0]
        ),
        message
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to verify product."
      });
    }
  }
);

/* -----------------------------
   BUSINESS STATISTICS
----------------------------- */

app.get(
  "/api/stats",
  auth,
  async (req, res) => {
    try {
      const products =
        await pool.query(
          `
          SELECT COUNT(*) AS count
          FROM products
          WHERE business_id = $1
          `,
          [req.business.id]
        );

      const checks =
        await pool.query(
          `
          SELECT COUNT(*) AS count
          FROM verifications v
          JOIN products p
            ON p.id = v.product_id
          WHERE p.business_id = $1
          `,
          [req.business.id]
        );

      const warnings =
        await pool.query(
          `
          SELECT COUNT(*) AS count
          FROM verifications v
          JOIN products p
            ON p.id = v.product_id
          WHERE p.business_id = $1
          AND v.result = 'warning'
          `,
          [req.business.id]
        );

      res.json({
        products:
          Number(products.rows[0].count),
        checks:
          Number(checks.rows[0].count),
        warnings:
          Number(warnings.rows[0].count)
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load statistics."
      });
    }
  }
);

/* -----------------------------
   FRONTEND
----------------------------- */

app.get("*", (_req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* -----------------------------
   START SERVER
----------------------------- */

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `VerifyIt V1.3 running on port ${PORT}`
      );
    });
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
