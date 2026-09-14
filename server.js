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
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const OWNER_KEY = process.env.VERIFYIT_OWNER_KEY || "";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* =========================================================
   DATABASE SETUP
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      business_id INTEGER NOT NULL,
      brand TEXT NOT NULL,
      product_name TEXT NOT NULL,
      batch TEXT DEFAULT '',
      code TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'active',
      verification_count INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      image_data TEXT DEFAULT '',
      FOREIGN KEY (business_id)
        REFERENCES businesses(id)
        ON DELETE CASCADE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS verifications (
      id SERIAL PRIMARY KEY,
      product_id INTEGER,
      code TEXT NOT NULL,
      result TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE SET NULL
    )
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS image_data TEXT DEFAULT ''
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS system_settings (
      setting_name TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS owner_audit_log (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      result TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  await pool.query(`
    INSERT INTO system_settings
      (setting_name, setting_value, updated_at)
    VALUES
      ('verifyit_lockdown', 'false', $1)
    ON CONFLICT (setting_name) DO NOTHING
  `, [now()]);
}

/* =========================================================
   BASIC HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

/* =========================================================
   VERIFYIT LOCK IN PROTOCOL
========================================================= */

async function getLockdownState() {
  const result = await pool.query(`
    SELECT setting_value
    FROM system_settings
    WHERE setting_name = 'verifyit_lockdown'
    LIMIT 1
  `);

  if (!result.rows.length) {
    throw new Error("Lockdown state is unavailable.");
  }

  return result.rows[0].setting_value === "true";
}

async function setLockdownState(locked) {
  await pool.query(`
    INSERT INTO system_settings
      (setting_name, setting_value, updated_at)
    VALUES
      ('verifyit_lockdown', $1, $2)
    ON CONFLICT (setting_name)
    DO UPDATE SET
      setting_value = EXCLUDED.setting_value,
      updated_at = EXCLUDED.updated_at
  `, [locked ? "true" : "false", now()]);
}

async function writeOwnerAudit(action, result) {
  try {
    await pool.query(`
      INSERT INTO owner_audit_log
        (action, result, created_at)
      VALUES
        ($1, $2, $3)
    `, [action, result, now()]);
  } catch (error) {
    console.error("Owner audit log failed:", error.message);
  }
}

function safeOwnerKeyCompare(providedKey) {
  if (!providedKey || !OWNER_KEY) {
    return false;
  }

  const providedBuffer = Buffer.from(String(providedKey));
  const ownerBuffer = Buffer.from(String(OWNER_KEY));

  if (providedBuffer.length !== ownerBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(providedBuffer, ownerBuffer);
}

async function ownerAuth(req, res, next) {
  const providedKey = req.header("x-verifyit-owner-key");

  if (!OWNER_KEY) {
    await writeOwnerAudit("owner_auth", "failed_owner_key_not_configured");

    return res.status(503).json({
      success: false,
      error: "Owner authentication is not configured."
    });
  }

  if (!safeOwnerKeyCompare(providedKey)) {
    await writeOwnerAudit("owner_auth", "failed_invalid_key");

    return res.status(401).json({
      success: false,
      error: "Invalid owner key."
    });
  }

  req.isVerifyItOwner = true;

  await writeOwnerAudit("owner_auth", "success");

  next();
}

async function lockdownMiddleware(req, res, next) {
  /*
    Owner-authenticated requests bypass lockdown.
  */
  if (req.isVerifyItOwner) {
    return next();
  }

  try {
    const locked = await getLockdownState();

    if (locked) {
      return res.status(503).json({
        success: false,
        locked: true,
        error: "VerifyIt is currently under lockdown."
      });
    }

    next();
  } catch (error) {
    console.error("Unable to determine lockdown state:", error.message);

    /*
      FAIL-SAFE:
      If VerifyIt cannot determine its lockdown state,
      protected API operations are blocked.
    */
    return res.status(503).json({
      success: false,
      locked: true,
      error: "VerifyIt is temporarily unavailable."
    });
  }
}

/* =========================================================
   PRODUCT CODE
========================================================= */

async function makeCode(db = pool) {
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
      await db.query(
        "SELECT 1 FROM products WHERE code = $1",
        [code]
      )
    ).rowCount
  );

  return code;
}

/* =========================================================
   JWT
========================================================= */

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

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "Please log in."
    });
  }

  const token = header.slice(7);

  try {
    req.business = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Please log in."
    });
  }
}

/* =========================================================
   PUBLIC PRODUCT FORMAT
========================================================= */

function publicProduct(product, includeImage = false) {
  const data = {
    brand: product.brand,
    productName: product.product_name,
    batch: product.batch || "",
    code: product.code,
    status: product.status,
    verificationCount: Number(product.verification_count || 0),
    createdAt: product.created_at
  };

  if (includeImage) {
    data.imageData = product.image_data || "";
  }

  return data;
}

/* =========================================================
   IMAGE VALIDATION
========================================================= */

function validImageData(imageData) {
  if (!imageData) {
    return true;
  }

  if (typeof imageData !== "string") {
    return false;
  }

  const validFormat =
    /^data:image\/(jpeg|jpg|png|webp);base64,/i.test(imageData);

  if (!validFormat) {
    return false;
  }

  /*
    Keep image payloads controlled.
  */
  if (imageData.length > 1500000) {
    return false;
  }

  return true;
}

/* =========================================================
   VERIFICATION URL
========================================================= */

function getVerificationUrl(req, code) {
  const base =
    process.env.PUBLIC_BASE_URL ||
    `${req.protocol}://${req.get("host")}`;

  return `${base}/?verify=${encodeURIComponent(code)}#verify`;
}

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: "5mb"
  })
);

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");

    let locked = true;

    try {
      locked = await getLockdownState();
    } catch {
      locked = true;
    }

    res.json({
      ok: true,
      service: "VerifyIt",
      version: "1.6.0",
      database: "postgresql",
      lockdown: locked
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(500).json({
      ok: false,
      service: "VerifyIt",
      error: "Database connection failed."
    });
  }
});

/* =========================================================
   OWNER LOCKDOWN STATUS
   Owner routes are intentionally BEFORE lockdown middleware.
========================================================= */

app.get(
  "/api/owner/lockdown-status",
  ownerAuth,
  async (_req, res) => {
    try {
      const locked = await getLockdownState();

      res.json({
        success: true,
        lockdown: locked
      });
    } catch (error) {
      console.error("Lockdown status error:", error.message);

      res.status(503).json({
        success: false,
        error: "Unable to determine lockdown state."
      });
    }
  }
);

/* =========================================================
   OWNER LOCKDOWN
========================================================= */

app.post(
  "/api/owner/lockdown",
  ownerAuth,
  async (_req, res) => {
    try {
      await setLockdownState(true);

      await writeOwnerAudit(
        "lockdown",
        "success"
      );

      res.json({
        success: true,
        lockdown: true
      });
    } catch (error) {
      console.error("Lockdown failed:", error.message);

      await writeOwnerAudit(
        "lockdown",
        "failed"
      );

      res.status(500).json({
        success: false,
        error: "Unable to activate lockdown."
      });
    }
  }
);

/* =========================================================
   OWNER UNLOCK
========================================================= */

app.post(
  "/api/owner/unlock",
  ownerAuth,
  async (_req, res) => {
    try {
      await setLockdownState(false);

      await writeOwnerAudit(
        "unlock",
        "success"
      );

      res.json({
        success: true,
        lockdown: false
      });
    } catch (error) {
      console.error("Unlock failed:", error.message);

      await writeOwnerAudit(
        "unlock",
        "failed"
      );

      res.status(500).json({
        success: false,
        error: "Unable to deactivate lockdown."
      });
    }
  }
);

/* =========================================================
   OWNER AUDIT LOG
========================================================= */

app.get(
  "/api/owner/audit-log",
  ownerAuth,
  async (_req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          action,
          result,
          created_at
        FROM owner_audit_log
        ORDER BY id DESC
        LIMIT 200
      `);

      res.json({
        success: true,
        logs: result.rows
      });
    } catch (error) {
      console.error("Audit log error:", error.message);

      res.status(500).json({
        success: false,
        error: "Unable to load audit log."
      });
    }
  }
);

/* =========================================================
   LOCKDOWN MIDDLEWARE
   Everything below this point is protected.
========================================================= */

app.use(
  "/api",
  lockdownMiddleware
);

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body || {};

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanName) {
      return res.status(400).json({
        success: false,
        error: "Business name is required."
      });
    }

    if (!cleanEmail) {
      return res.status(400).json({
        success: false,
        error: "Email is required."
      });
    }

    if (!password || String(password).length < 8) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters."
      });
    }

    const passwordHash = await bcrypt.hash(
      String(password),
      12
    );

    const result = await pool.query(
      `
        INSERT INTO businesses
          (name, email, password_hash, created_at)
        VALUES
          ($1, $2, $3, $4)
        RETURNING id, name, email, created_at
      `,
      [
        cleanName,
        cleanEmail,
        passwordHash,
        now()
      ]
    );

    const business = result.rows[0];

    res.status(201).json({
      success: true,
      token: tokenFor(business),
      business
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "Email is already registered."
      });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
      success: false,
      error: "Unable to create business account."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body || {};

    const cleanEmail =
      String(email || "")
        .trim()
        .toLowerCase();

    const result = await pool.query(
      `
        SELECT *
        FROM businesses
        WHERE LOWER(email) = $1
        LIMIT 1
      `,
      [cleanEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password."
      });
    }

    const business = result.rows[0];

    const validPassword =
      await bcrypt.compare(
        String(password || ""),
        business.password_hash
      );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password."
      });
    }

    res.json({
      success: true,
      token: tokenFor(business),
      business: {
        id: business.id,
        name: business.name,
        email: business.email
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      success: false,
      error: "Unable to log in."
    });
  }
});

/* =========================================================
   CURRENT BUSINESS
========================================================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          SELECT
            id,
            name,
            email,
            created_at
          FROM businesses
          WHERE id = $1
          LIMIT 1
        `,
        [req.business.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Business account not found."
        });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Current business error:", error.message);

      res.status(500).json({
        success: false,
        error: "Unable to load business account."
      });
    }
  }
);

/* =========================================================
   SINGLE PRODUCT REGISTRATION
========================================================= */

app.post(
  "/api/products",
  auth,
  async (req, res) => {
    try {
      const {
        brand,
        productName,
        batch,
        imageData
      } = req.body || {};

      const cleanBrand =
        String(brand || "").trim();

      const cleanProductName =
        String(productName || "").trim();

      const cleanBatch =
        String(batch || "").trim();

      if (!cleanBrand) {
        return res.status(400).json({
          success: false,
          error: "Brand is required."
        });
      }

      if (!cleanProductName) {
        return res.status(400).json({
          success: false,
          error: "Product name is required."
        });
      }

      if (!validImageData(imageData)) {
        return res.status(400).json({
          success: false,
          error: "Invalid or oversized image."
        });
      }

      const code = await makeCode();

      const result = await pool.query(
        `
          INSERT INTO products
            (
              business_id,
              brand,
              product_name,
              batch,
              code,
              status,
              verification_count,
              created_at,
              image_data
            )
          VALUES
            ($1, $2, $3, $4, $5, 'active', 0, $6, $7)
          RETURNING *
        `,
        [
          req.business.id,
          cleanBrand,
          cleanProductName,
          cleanBatch,
          code,
          now(),
          imageData || ""
        ]
      );

      res.status(201).json({
        success: true,
        product: publicProduct(
          result.rows[0],
          true
        )
      });
    } catch (error) {
      console.error(
        "Product registration error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to register product."
      });
    }
  }
);

/* =========================================================
   V1.6 BULK PRODUCT REGISTRATION
========================================================= */

app.post(
  "/api/products/bulk",
  auth,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const products = req.body?.products;

      if (!Array.isArray(products)) {
        return res.status(400).json({
          success: false,
          error: "products must be an array."
        });
      }

      if (products.length === 0) {
        return res.status(400).json({
          success: false,
          error: "No products were provided."
        });
      }

      /*
        V1.6 limit:
        50 products per import.
      */
      if (products.length > 50) {
        return res.status(400).json({
          success: false,
          error: "A maximum of 50 products can be imported at once."
        });
      }

      /*
        Validate every row BEFORE starting the transaction.
        This prevents partially valid imports.
      */
      const validatedProducts = [];

      for (let index = 0; index < products.length; index++) {
        const item = products[index] || {};

        const brand =
          String(item.brand || "").trim();

        const productName =
          String(item.productName || "").trim();

        const batch =
          String(item.batch || "").trim();

        if (!brand) {
          return res.status(400).json({
            success: false,
            error: `Row ${index + 1}: Brand is required.`
          });
        }

        if (!productName) {
          return res.status(400).json({
            success: false,
            error: `Row ${index + 1}: Product name is required.`
          });
        }

        /*
          Bulk import intentionally does not accept
          imageData in V1.6.
        */
        validatedProducts.push({
          brand,
          productName,
          batch
        });
      }

      await client.query("BEGIN");

      const createdProducts = [];

      for (const item of validatedProducts) {
        const code = await makeCode(client);
        const createdAt = now();

        const result = await client.query(
          `
            INSERT INTO products
              (
                business_id,
                brand,
                product_name,
                batch,
                code,
                status,
                verification_count,
                created_at,
                image_data
              )
            VALUES
              ($1, $2, $3, $4, $5, 'active', 0, $6, '')
            RETURNING *
          `,
          [
            req.business.id,
            item.brand,
            item.productName,
            item.batch,
            code,
            createdAt
          ]
        );

        const product = result.rows[0];

        /*
          Automatic QR generation.
        */
        const verifyUrl =
          getVerificationUrl(
            req,
            product.code
          );

        const qrData =
          await QRCode.toDataURL(
            verifyUrl,
            {
              margin: 2,
              width: 600
            }
          );

        createdProducts.push({
          ...publicProduct(product, false),
          qrUrl: verifyUrl,
          qrData
        });
      }

      await client.query("COMMIT");

      res.status(201).json({
        success: true,
        count: createdProducts.length,
        products: createdProducts
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(
        "Bulk product import error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Bulk product import failed. No products were saved."
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   PRODUCT CATALOG
========================================================= */

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

      res.json({
        success: true,
        products: result.rows.map(
          product => publicProduct(product, false)
        )
      });
    } catch (error) {
      console.error(
        "Product catalog error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to load products."
      });
    }
  }
);

/* =========================================================
   PRODUCT IMAGE
========================================================= */

app.get(
  "/api/products/:code/image",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          SELECT image_data
          FROM products
          WHERE code = $1
            AND business_id = $2
          LIMIT 1
        `,
        [
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Product not found."
        });
      }

      res.json({
        success: true,
        imageData:
          result.rows[0].image_data || ""
      });
    } catch (error) {
      console.error(
        "Product image error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to load product image."
      });
    }
  }
);

/* =========================================================
   UPDATE PRODUCT IMAGE
========================================================= */

app.patch(
  "/api/products/:code/image",
  auth,
  async (req, res) => {
    try {
      const {
        imageData
      } = req.body || {};

      if (!validImageData(imageData)) {
        return res.status(400).json({
          success: false,
          error: "Invalid or oversized image."
        });
      }

      const result = await pool.query(
        `
          UPDATE products
          SET image_data = $1
          WHERE code = $2
            AND business_id = $3
          RETURNING *
        `,
        [
          imageData || "",
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Product not found."
        });
      }

      res.json({
        success: true,
        product: publicProduct(
          result.rows[0],
          true
        )
      });
    } catch (error) {
      console.error(
        "Update image error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to update product image."
      });
    }
  }
);

/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/products/:code",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          DELETE FROM products
          WHERE code = $1
            AND business_id = $2
          RETURNING id
        `,
        [
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Product not found."
        });
      }

      res.json({
        success: true,
        message: "Product deleted."
      });
    } catch (error) {
      console.error(
        "Delete product error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to delete product."
      });
    }
  }
);

/* =========================================================
   UPDATE PRODUCT STATUS
========================================================= */

app.patch(
  "/api/products/:code/status",
  auth,
  async (req, res) => {
    try {
      const {
        status
      } = req.body || {};

      const allowedStatuses = [
        "active",
        "disabled",
        "recalled"
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: "Invalid product status."
        });
      }

      const result = await pool.query(
        `
          UPDATE products
          SET status = $1
          WHERE code = $2
            AND business_id = $3
          RETURNING *
        `,
        [
          status,
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Product not found."
        });
      }

      res.json({
        success: true,
        product: publicProduct(
          result.rows[0],
          false
        )
      });
    } catch (error) {
      console.error(
        "Product status error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to update product status."
      });
    }
  }
);

/* =========================================================
   PRODUCT QR
========================================================= */

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
          LIMIT 1
        `,
        [
          req.params.code,
          req.business.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          error: "Product not found."
        });
      }

      const product = result.rows[0];

      const verifyUrl =
        getVerificationUrl(
          req,
          product.code
        );

      const data =
        await QRCode.toDataURL(
          verifyUrl,
          {
            margin: 2,
            width: 600
          }
        );

      res.json({
        success: true,
        url: verifyUrl,
        data
      });
    } catch (error) {
      console.error(
        "QR generation error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to generate QR code."
      });
    }
  }
);

/* =========================================================
   PUBLIC PRODUCT VERIFICATION
========================================================= */

app.get(
  "/api/verify/:code",
  async (req, res) => {
    try {
      const code =
        String(req.params.code || "")
          .trim()
          .toUpperCase();

      const result = await pool.query(
        `
          SELECT *
          FROM products
          WHERE code = $1
          LIMIT 1
        `,
        [code]
      );

      if (!result.rows.length) {
        await pool.query(
          `
            INSERT INTO verifications
              (
                product_id,
                code,
                result,
                checked_at
              )
            VALUES
              (NULL, $1, 'not_verified', $2)
          `,
          [
            code,
            now()
          ]
        );

        return res.status(404).json({
          success: false,
          result: "not_verified",
          message: "Product could not be verified."
        });
      }

      const product = result.rows[0];

      const warning =
        product.status !== "active" ||
        Number(product.verification_count || 0) >= 5;

      const verificationResult =
        warning
          ? "warning"
          : "authentic";

      await pool.query(
        `
          UPDATE products
          SET verification_count =
            COALESCE(verification_count, 0) + 1
          WHERE id = $1
        `,
        [product.id]
      );

      await pool.query(
        `
          INSERT INTO verifications
            (
              product_id,
              code,
              result,
              checked_at
            )
          VALUES
            ($1, $2, $3, $4)
        `,
        [
          product.id,
          code,
          verificationResult,
          now()
        ]
      );

      const refreshed =
        await pool.query(
          `
            SELECT *
            FROM products
            WHERE id = $1
            LIMIT 1
          `,
          [product.id]
        );

      const finalProduct =
        refreshed.rows[0] || product;

      res.json({
        success: true,
        result: verificationResult,
        product: publicProduct(
          finalProduct,
          true
        ),
        message:
          verificationResult === "authentic"
            ? "Product verified successfully."
            : "Warning: this product requires attention."
      });
    } catch (error) {
      console.error(
        "Verification error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to verify product."
      });
    }
  }
);

/* =========================================================
   BUSINESS STATS
========================================================= */

app.get(
  "/api/stats",
  auth,
  async (req, res) => {
    try {
      const productCount =
        await pool.query(
          `
            SELECT COUNT(*)::int AS count
            FROM products
            WHERE business_id = $1
          `,
          [req.business.id]
        );

      const verificationCount =
        await pool.query(
          `
            SELECT COUNT(*)::int AS count
            FROM verifications v
            INNER JOIN products p
              ON p.id = v.product_id
            WHERE p.business_id = $1
          `,
          [req.business.id]
        );

      const warningCount =
        await pool.query(
          `
            SELECT COUNT(*)::int AS count
            FROM verifications v
            INNER JOIN products p
              ON p.id = v.product_id
            WHERE p.business_id = $1
              AND v.result = 'warning'
          `,
          [req.business.id]
        );

      res.json({
        success: true,
        products:
          Number(productCount.rows[0].count),

        totalChecks:
          Number(verificationCount.rows[0].count),

        warnings:
          Number(warningCount.rows[0].count)
      });
    } catch (error) {
      console.error(
        "Stats error:",
        error.message
      );

      res.status(500).json({
        success: false,
        error: "Unable to load statistics."
      });
    }
  }
);

/* =========================================================
   OWNER CONTROL PAGE
========================================================= */

app.get("/owner", (_req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VerifyIt Owner Control</title>

  <style>
    body {
      margin: 0;
      padding: 30px;
      font-family: Arial, sans-serif;
      background: #111;
      color: #fff;
    }

    .container {
      max-width: 700px;
      margin: 0 auto;
    }

    h1 {
      margin-bottom: 8px;
    }

    .card {
      background: #1d1d1d;
      border: 1px solid #333;
      border-radius: 12px;
      padding: 20px;
      margin-top: 20px;
    }

    input {
      width: 100%;
      box-sizing: border-box;
      padding: 12px;
      margin: 8px 0 12px;
      border-radius: 8px;
      border: 1px solid #444;
      background: #111;
      color: #fff;
    }

    button {
      padding: 12px 16px;
      margin: 5px;
      border: 0;
      border-radius: 8px;
      cursor: pointer;
      font-weight: bold;
    }

    #status {
      margin-top: 15px;
      padding: 12px;
      border-radius: 8px;
      background: #111;
    }

    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: #111;
      padding: 15px;
      border-radius: 8px;
      overflow-x: auto;
    }
  </style>
</head>

<body>

<div class="container">

  <h1>VerifyIt Owner Control</h1>
  <p>VerifyIt Lock In Protocol</p>

  <div class="card">

    <label>Owner Key</label>

    <input
      id="ownerKey"
      type="password"
      placeholder="Enter VERIFYIT_OWNER_KEY"
    >

    <button onclick="checkStatus()">
      Check Status
    </button>

    <button onclick="lockSystem()">
      LOCK VERIFYIT
    </button>

    <button onclick="unlockSystem()">
      UNLOCK VERIFYIT
    </button>

    <div id="status">
      Status unknown.
    </div>

  </div>

  <div class="card">

    <h2>Audit Log</h2>

    <button onclick="loadAudit()">
      Refresh Audit Log
    </button>

    <pre id="audit">No audit data loaded.</pre>

  </div>

</div>

<script>

  const keyInput =
    document.getElementById("ownerKey");

  const statusBox =
    document.getElementById("status");

  const auditBox =
    document.getElementById("audit");

  function headers() {
    return {
      "x-verifyit-owner-key":
        keyInput.value.trim()
    };
  }

  async function checkStatus() {
    try {
      const response =
        await fetch(
          "/api/owner/lockdown-status",
          {
            headers: headers()
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Unable to check status."
        );
      }

      statusBox.textContent =
        data.lockdown
          ? "🔒 VERIFYIT IS LOCKED"
          : "🟢 VERIFYIT IS UNLOCKED";

    } catch (error) {
      statusBox.textContent =
        error.message;
    }
  }

  async function lockSystem() {
    try {
      const response =
        await fetch(
          "/api/owner/lockdown",
          {
            method: "POST",
            headers: headers()
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Unable to lock VerifyIt."
        );
      }

      statusBox.textContent =
        "🔒 VERIFYIT IS NOW LOCKED";

    } catch (error) {
      statusBox.textContent =
        error.message;
    }
  }

  async function unlockSystem() {
    try {
      const response =
        await fetch(
          "/api/owner/unlock",
          {
            method: "POST",
            headers: headers()
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Unable to unlock VerifyIt."
        );
      }

      statusBox.textContent =
        "🟢 VERIFYIT IS NOW UNLOCKED";

    } catch (error) {
      statusBox.textContent =
        error.message;
    }
  }

  async function loadAudit() {
    try {
      const response =
        await fetch(
          "/api/owner/audit-log",
          {
            headers: headers()
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Unable to load audit log."
        );
      }

      auditBox.textContent =
        JSON.stringify(
          data.logs,
          null,
          2
        );

    } catch (error) {
      auditBox.textContent =
        error.message;
    }
  }

</script>

</body>
</html>
  `);
});

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get("*", (_req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================================================
   START SERVER
========================================================= */

initDatabase()
  .then(() => {

    if (!OWNER_KEY) {
      console.warn(
        "WARNING: VERIFYIT_OWNER_KEY is not configured."
      );
    }

    app.listen(
      PORT,
      () => {
        console.log(
          `VerifyIt V1.6 with Lock In Protocol running on port ${PORT}`
        );
      }
    );

  })
  .catch(error => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
