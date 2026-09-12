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

const OWNER_KEY =
  process.env.VERIFYIT_OWNER_KEY || "";

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

  /*
    IMPORTANT:
    Each PostgreSQL command is executed separately.
    This avoids:
    "cannot insert multiple commands into a prepared statement"
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
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
      code TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'active',
      verification_count INTEGER NOT NULL DEFAULT 0,
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

  /*
    Persistent system settings.
    This survives server restarts and redeployments.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS system_settings (
      setting_name TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  /*
    Owner audit log.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS owner_audit_log (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      result TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  /*
    Create the default lockdown state only if it
    does not already exist.

    IMPORTANT:
    ON CONFLICT DO NOTHING means an existing
    lockdown state is preserved.
  */

  await pool.query(
    `
      INSERT INTO system_settings
      (
        setting_name,
        setting_value,
        updated_at
      )
      VALUES ($1, $2, $3)
      ON CONFLICT (setting_name)
      DO NOTHING
    `,
    [
      "verifyit_lockdown",
      "false",
      now()
    ]
  );

  console.log(
    "VerifyIt PostgreSQL database ready."
  );
}

/* -----------------------------
   TIME
----------------------------- */

function now() {
  return new Date().toISOString();
}

/* -----------------------------
   LOCKDOWN HELPERS
----------------------------- */

async function getLockdownState() {

  const result = await pool.query(
    `
      SELECT setting_value
      FROM system_settings
      WHERE setting_name = $1
    `,
    ["verifyit_lockdown"]
  );

  if (!result.rows[0]) {
    throw new Error(
      "Lockdown state is unavailable."
    );
  }

  return (
    result.rows[0].setting_value === "true"
  );
}


async function setLockdownState(locked) {

  await pool.query(
    `
      INSERT INTO system_settings
      (
        setting_name,
        setting_value,
        updated_at
      )
      VALUES ($1, $2, $3)

      ON CONFLICT (setting_name)
      DO UPDATE SET
        setting_value = EXCLUDED.setting_value,
        updated_at = EXCLUDED.updated_at
    `,
    [
      "verifyit_lockdown",
      locked ? "true" : "false",
      now()
    ]
  );
}


async function writeOwnerAudit(
  action,
  result
) {

  try {

    await pool.query(
      `
        INSERT INTO owner_audit_log
        (
          action,
          result,
          created_at
        )
        VALUES ($1, $2, $3)
      `,
      [
        action,
        result,
        now()
      ]
    );

  } catch (error) {

    console.error(
      "Owner audit logging failed:",
      error
    );
  }
}


/* -----------------------------
   OWNER KEY SECURITY
----------------------------- */

function safeOwnerKeyCompare(
  providedKey
) {

  if (!OWNER_KEY) {
    return false;
  }

  if (
    typeof providedKey !== "string"
  ) {
    return false;
  }

  const providedBuffer =
    Buffer.from(
      providedKey,
      "utf8"
    );

  const ownerBuffer =
    Buffer.from(
      OWNER_KEY,
      "utf8"
    );

  if (
    providedBuffer.length !==
    ownerBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    providedBuffer,
    ownerBuffer
  );
}


/* -----------------------------
   OWNER AUTHENTICATION
----------------------------- */

function ownerAuth(
  req,
  res,
  next
) {

  if (!OWNER_KEY) {

    return res.status(503).json({
      success: false,
      error:
        "Owner controls are not configured."
    });
  }

  const providedKey =
    req.headers[
      "x-verifyit-owner-key"
    ];

  if (
    !safeOwnerKeyCompare(
      providedKey
    )
  ) {

    writeOwnerAudit(
      "OWNER_AUTH",
      "FAILED"
    );

    return res.status(401).json({
      success: false,
      error:
        "Owner authentication failed."
    });
  }

  req.isVerifyItOwner = true;

  next();
}


/* -----------------------------
   LOCKDOWN MIDDLEWARE
----------------------------- */

async function lockdownMiddleware(
  req,
  res,
  next
) {

  /*
    Owner-authenticated requests are
    allowed through.
  */

  if (req.isVerifyItOwner) {
    return next();
  }

  try {

    const locked =
      await getLockdownState();

    if (locked) {

      return res.status(503).json({
        success: false,
        locked: true,
        error:
          "VerifyIt is currently under lockdown."
      });
    }

    next();

  } catch (error) {

    console.error(
      "Unable to determine lockdown state:",
      error
    );

    /*
      FAIL SAFE:
      If the system cannot determine whether
      it is locked, protected operations are blocked.
    */

    return res.status(503).json({
      success: false,
      locked: true,
      error:
        "VerifyIt is temporarily unavailable."
    });
  }
}


/* -----------------------------
   CODE GENERATOR
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


/* -----------------------------
   JWT
----------------------------- */

function tokenFor(
  business
) {

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


/* -----------------------------
   BUSINESS AUTH
----------------------------- */

function auth(
  req,
  res,
  next
) {

  try {

    const header =
      req.headers.authorization || "";

    if (
      !header.startsWith(
        "Bearer "
      )
    ) {
      throw new Error(
        "Missing token"
      );
    }

    req.business =
      jwt.verify(
        header.slice(7),
        JWT_SECRET
      );

    next();

  } catch {

    res.status(401).json({
      error:
        "Please log in."
    });
  }
}


/* -----------------------------
   PUBLIC PRODUCT DATA
----------------------------- */

function publicProduct(
  product,
  includeImage = false
) {

  const result = {

    brand:
      product.brand,

    productName:
      product.product_name,

    batch:
      product.batch,

    code:
      product.code,

    status:
      product.status,

    verificationCount:
      Number(
        product.verification_count
      ),

    createdAt:
      product.created_at
  };

  if (includeImage) {

    result.imageData =
      product.image_data || "";
  }

  return result;
}


/* -----------------------------
   IMAGE VALIDATION
----------------------------- */

function validImageData(
  imageData
) {

  if (!imageData) {
    return true;
  }

  if (
    typeof imageData !==
    "string"
  ) {
    return false;
  }

  const validPrefix =
    /^data:image\/(jpeg|jpg|png|webp);base64,/i;

  if (
    !validPrefix.test(
      imageData
    )
  ) {
    return false;
  }

  /*
    Keep the prototype reasonably small.
  */

  if (
    imageData.length >
    1500000
  ) {
    return false;
  }

  return true;
}


/* -----------------------------
   EXPRESS
----------------------------- */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);


/* -----------------------------
   HEALTH CHECK
----------------------------- */

app.get(
  "/api/health",
  async (_req, res) => {

    try {

      await pool.query(
        "SELECT 1"
      );

      let locked = false;

      try {

        locked =
          await getLockdownState();

      } catch {

        locked = true;
      }

      res.json({

        ok: true,

        service:
          "VerifyIt",

        version:
          "1.5.0",

        database:
          "postgresql",

        lockdown:
          locked
      });

    } catch {

      res.status(500).json({

        ok: false,

        error:
          "Database connection failed."
      });
    }
  }
);


/* -----------------------------
   OWNER STATUS
----------------------------- */

app.get(
  "/api/owner/lockdown-status",
  ownerAuth,
  async (_req, res) => {

    try {

      const locked =
        await getLockdownState();

      res.json({

        success: true,

        locked
      });

    } catch (error) {

      console.error(error);

      res.status(503).json({

        success: false,

        error:
          "Unable to determine lockdown state."
      });
    }
  }
);


/* -----------------------------
   OWNER LOCK
----------------------------- */

app.post(
  "/api/owner/lockdown",
  ownerAuth,
  async (_req, res) => {

    try {

      await setLockdownState(
        true
      );

      await writeOwnerAudit(
        "LOCKDOWN",
        "SUCCESS"
      );

      res.json({

        success: true,

        locked: true,

        message:
          "VerifyIt lockdown activated."
      });

    } catch (error) {

      console.error(error);

      await writeOwnerAudit(
        "LOCKDOWN",
        "FAILED"
      );

      res.status(500).json({

        success: false,

        error:
          "Unable to activate lockdown."
      });
    }
  }
);


/* -----------------------------
   OWNER UNLOCK
----------------------------- */

app.post(
  "/api/owner/unlock",
  ownerAuth,
  async (_req, res) => {

    try {

      await setLockdownState(
        false
      );

      await writeOwnerAudit(
        "UNLOCK",
        "SUCCESS"
      );

      res.json({

        success: true,

        locked: false,

        message:
          "VerifyIt lockdown deactivated."
      });

    } catch (error) {

      console.error(error);

      await writeOwnerAudit(
        "UNLOCK",
        "FAILED"
      );

      res.status(500).json({

        success: false,

        error:
          "Unable to deactivate lockdown."
      });
    }
  }
);


/* -----------------------------
   OWNER AUDIT LOG
----------------------------- */

app.get(
  "/api/owner/audit-log",
  ownerAuth,
  async (_req, res) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              id,
              action,
              result,
              created_at
            FROM owner_audit_log
            ORDER BY id DESC
            LIMIT 100
          `
        );

      res.json({

        success: true,

        logs:
          result.rows
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        success: false,

        error:
          "Unable to load audit log."
      });
    }
  }
);


/* =========================================================
   LOCKDOWN PROTECTION
   ========================================================= */

app.use(
  "/api",
  lockdownMiddleware
);


/* -----------------------------
   BUSINESS REGISTRATION
----------------------------- */

app.post(
  "/api/register",
  async (req, res) => {

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

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `
            INSERT INTO businesses
            (
              name,
              email,
              password_hash,
              created_at
            )
            VALUES
            ($1, $2, $3, $4)
            RETURNING id, name, email
          `,
          [
            String(name)
              .trim(),

            String(email)
              .trim()
              .toLowerCase(),

            hash,

            now()
          ]
        );

      const business =
        result.rows[0];

      res.status(201).json({

        token:
          tokenFor(
            business
          ),

        business
      });

    } catch (error) {

      if (
        error.code ===
        "23505"
      ) {

        return res.status(409).json({

          error:
            "That email is already registered."
        });
      }

      console.error(error);

      res.status(500).json({

        error:
          "Unable to create account."
      });
    }
  }
);


/* -----------------------------
   BUSINESS LOGIN
----------------------------- */

app.post(
  "/api/login",
  async (req, res) => {

    const {
      email,
      password
    } = req.body || {};

    try {

      const result =
        await pool.query(
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

      const business =
        result.rows[0];

      if (
        !business ||
        !(await bcrypt.compare(
          String(password || ""),
          business.password_hash
        ))
      ) {

        return res.status(401).json({

          error:
            "Invalid email or password."
        });
      }

      res.json({

        token:
          tokenFor(
            business
          ),

        business: {

          id:
            business.id,

          name:
            business.name,

          email:
            business.email
        }
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to log in."
      });
    }
  }
);


/* -----------------------------
   CURRENT BUSINESS
----------------------------- */

app.get(
  "/api/me",
  auth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              created_at
            FROM businesses
            WHERE id = $1
          `,
          [
            req.business.id
          ]
        );

      if (!result.rows[0]) {

        return res.status(404).json({

          error:
            "Business not found."
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to load account."
      });
    }
  }
);


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
      batch,
      imageData
    } = req.body || {};

    if (
      !brand ||
      !productName
    ) {

      return res.status(400).json({

        error:
          "Brand and product name are required."
      });
    }

    if (
      !validImageData(
        imageData
      )
    ) {

      return res.status(400).json({

        error:
          "Invalid or oversized product image."
      });
    }

    try {

      const code =
        await makeCode();

      const createdAt =
        now();

      const result =
        await pool.query(
          `
            INSERT INTO products
            (
              business_id,
              brand,
              product_name,
              batch,
              code,
              created_at,
              image_data
            )
            VALUES
            ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
          `,
          [
            req.business.id,

            String(brand)
              .trim(),

            String(productName)
              .trim(),

            String(batch || "")
              .trim(),

            code,

            createdAt,

            String(
              imageData || ""
            )
          ]
        );

      res.status(201).json(

        publicProduct(
          result.rows[0],
          true
        )

      );

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to register product."
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

      const result =
        await pool.query(
          `
            SELECT *
            FROM products
            WHERE business_id = $1
            ORDER BY id DESC
          `,
          [
            req.business.id
          ]
        );

      res.json(

        result.rows.map(
          product =>
            publicProduct(
              product,
              false
            )
        )

      );

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to load products."
      });
    }
  }
);


/* -----------------------------
   GET PRODUCT IMAGE
----------------------------- */

app.get(
  "/api/products/:code/image",
  auth,
  async (req, res) => {

    const code =
      String(
        req.params.code || ""
      )
        .trim()
        .toUpperCase();

    try {

      const result =
        await pool.query(
          `
            SELECT image_data
            FROM products
            WHERE code = $1
            AND business_id = $2
          `,
          [
            code,
            req.business.id
          ]
        );

      const product =
        result.rows[0];

      if (!product) {

        return res.status(404).json({

          error:
            "Product not found."
        });
      }

      res.json({

        imageData:
          product.image_data || ""
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to load product image."
      });
    }
  }
);


/* -----------------------------
   REPLACE PRODUCT IMAGE
----------------------------- */

app.patch(
  "/api/products/:code/image",
  auth,
  async (req, res) => {

    const code =
      String(
        req.params.code || ""
      )
        .trim()
        .toUpperCase();

    const {
      imageData
    } = req.body || {};

    if (
      !validImageData(
        imageData
      )
    ) {

      return res.status(400).json({

        error:
          "Invalid or oversized product image."
      });
    }

    try {

      const result =
        await pool.query(
          `
            UPDATE products
            SET image_data = $1
            WHERE code = $2
            AND business_id = $3
            RETURNING *
          `,
          [
            String(
              imageData || ""
            ),

            code,

            req.business.id
          ]
        );

      if (!result.rowCount) {

        return res.status(404).json({

          error:
            "Product not found."
        });
      }

      res.json({

        ok: true,

        product:
          publicProduct(
            result.rows[0],
            true
          )
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to update product image."
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

    const code =
      String(
        req.params.code || ""
      )
        .trim()
        .toUpperCase();

    try {

      const result =
        await pool.query(
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

          error:
            "Product not found."
        });
      }

      res.json({

        ok: true,

        message:
          "Product deleted."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to delete product."
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

    const status =
      req.body?.status;

    if (
      ![
        "active",
        "disabled",
        "recalled"
      ].includes(status)
    ) {

      return res.status(400).json({

        error:
          "Invalid status."
      });
    }

    try {

      const result =
        await pool.query(
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

          error:
            "Product not found."
        });
      }

      res.json({

        ok: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({

        error:
          "Unable to update product."
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

      const result =
        await pool.query(
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

      const product =
        result.rows[0];

      if (!product) {

        return res.status(404).json({

          error:
            "Product not found."
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

        url:
          verifyUrl,

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

    const code =
      String(
        req.params.code || ""
      )
        .trim()
        .toUpperCase();

    try {

      const result =
        await pool.query(
          `
            SELECT *
            FROM products
            WHERE code = $1
          `,
          [
            code
          ]
        );

      const product =
        result.rows[0];

      /*
        Code doesn't exist.
      */

      if (!product) {

        await pool.query(
          `
            INSERT INTO verifications
            (
              code,
              result,
              checked_at
            )
            VALUES
            ($1, $2, $3)
          `,
          [
            code,
            "not_verified",
            now()
          ]
        );

        return res.json({

          result:
            "not_verified",

          message:
            "This code is not registered in the VerifyIt database."
        });
      }

      /*
        Determine result.
      */

      let verificationResult;

      if (
        product.status !==
        "active"
      ) {

        verificationResult =
          "warning";

      } else if (
        Number(
          product.verification_count
        ) >= 5
      ) {

        verificationResult =
          "warning";

      } else {

        verificationResult =
          "authentic";
      }

      let message;

      if (
        product.status !==
        "active"
      ) {

        message =
          `This product record is marked ${product.status}.`;

      } else if (
        verificationResult ===
        "warning"
      ) {

        message =
          "This code is registered, but it has unusually high verification activity. Check the item with the seller or manufacturer.";

      } else {

        message =
          "The code matches a registered product record.";
      }

      /*
        Increase verification count.
      */

      await pool.query(
        `
          UPDATE products
          SET verification_count =
            verification_count + 1
          WHERE id = $1
        `,
        [
          product.id
        ]
      );

      /*
        Record verification.
      */

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

      /*
        Get updated product.
      */

      const freshResult =
        await pool.query(
          `
            SELECT *
            FROM products
            WHERE id = $1
          `,
          [
            product.id
          ]
        );

      res.json({

        result:
          verificationResult,

        product:
          publicProduct(
            freshResult.rows[0],
            true
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
          [
            req.business.id
          ]
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
          [
            req.business.id
          ]
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
          [
            req.business.id
          ]
        );

      res.json({

        products:
          Number(
            products.rows[0].count
          ),

        checks:
          Number(
            checks.rows[0].count
          ),

        warnings:
          Number(
            warnings.rows[0].count
          )
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


/* =========================================================
   OWNER CONTROL PAGE
   ========================================================= */

app.get(
  "/owner",
  (_req, res) => {

    res.type("html").send(`

<!DOCTYPE html>

<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >

  <title>
    VerifyIt Owner Control
  </title>

  <style>

    * {
      box-sizing: border-box;
    }

    body {

      margin: 0;

      padding: 20px;

      min-height: 100vh;

      background: #111;

      color: #fff;

      font-family:
        Arial,
        Helvetica,
        sans-serif;
    }

    .box {

      width: 100%;

      max-width: 500px;

      margin:
        40px auto;

      padding: 25px;

      background: #1c1c1c;

      border-radius: 16px;

      box-shadow:
        0 0 25px
        rgba(0, 0, 0, 0.4);
    }

    h1 {

      margin-top: 0;

      margin-bottom: 10px;
    }

    .subtitle {

      color: #aaa;

      margin-bottom: 25px;
    }

    .status {

      padding: 18px;

      margin:
        20px 0;

      border-radius: 10px;

      background: #292929;

      font-weight: bold;

      text-align: center;
    }

    input {

      width: 100%;

      padding: 14px;

      margin-bottom: 15px;

      border-radius: 8px;

      border:
        1px solid #555;

      background: #111;

      color: white;

      font-size: 16px;
    }

    button {

      width: 100%;

      padding: 15px;

      margin-top: 10px;

      border: 0;

      border-radius: 8px;

      font-size: 16px;

      font-weight: bold;

      cursor: pointer;
    }

    button:active {

      transform:
        scale(0.98);
    }

    .lock {

      background: #b00020;

      color: white;
    }

    .unlock {

      background: #087f23;

      color: white;
    }

    .refresh {

      background: #444;

      color: white;
    }

    #message {

      margin-top: 20px;

      padding: 10px;

      white-space:
        pre-wrap;

      line-height: 1.5;
    }

  </style>

</head>

<body>

  <div class="box">

    <h1>
      VerifyIt Owner Control
    </h1>

    <div class="subtitle">
      Emergency system control
    </div>

    <div
      id="status"
      class="status"
    >
      Checking system status...
    </div>

    <input
      id="ownerKey"
      type="password"
      placeholder="Enter owner key"
      autocomplete="off"
    >

    <button
      class="lock"
      onclick="changeLock(true)"
    >
      🔒 LOCK VERIFYIT
    </button>

    <button
      class="unlock"
      onclick="changeLock(false)"
    >
      🔓 UNLOCK VERIFYIT
    </button>

    <button
      class="refresh"
      onclick="loadStatus()"
    >
      🔄 REFRESH STATUS
    </button>

    <div
      id="message"
    ></div>

  </div>


<script>

async function loadStatus() {

  const status =
    document.getElementById(
      "status"
    );

  const message =
    document.getElementById(
      "message"
    );

  status.textContent =
    "Checking system status...";

  message.textContent =
    "";

  try {

    const response =
      await fetch(
        "/api/owner/lockdown-status"
      );

    const data =
      await response.json();

    if (!response.ok) {

      throw new Error(
        data.error ||
        "Unable to read status."
      );
    }

    if (data.locked) {

      status.textContent =
        "🔒 VERIFYIT IS LOCKED";

    } else {

      status.textContent =
        "🟢 VERIFYIT IS UNLOCKED";
    }

  } catch (error) {

    status.textContent =
      "⚠️ Unable to read status.";

    message.textContent =
      error.message;
  }
}


async function changeLock(
  locked
) {

  const keyInput =
    document.getElementById(
      "ownerKey"
    );

  const message =
    document.getElementById(
      "message"
    );

  const key =
    keyInput.value;

  if (!key) {

    message.textContent =
      "Enter your owner key first.";

    return;
  }

  const endpoint =
    locked
      ? "/api/owner/lockdown"
      : "/api/owner/unlock";

  message.textContent =
    locked
      ? "Activating lockdown..."
      : "Restoring VerifyIt...";

  try {

    const response =
      await fetch(
        endpoint,
        {
          method: "POST",

          headers: {
            "x-verifyit-owner-key":
              key
          }
        }
      );

    const data =
      await response.json();

    if (!response.ok) {

      throw new Error(
        data.error ||
        "Request failed."
      );
    }

    message.textContent =
      locked
        ? "🔒 Lockdown activated successfully."
        : "🔓 VerifyIt restored successfully.";

    keyInput.value =
      "";

    await loadStatus();

  } catch (error) {

    message.textContent =
      "⚠️ " +
      error.message;
  }
}


loadStatus();

</script>

</body>

</html>

    `);
  }
);


/* -----------------------------
   FRONTEND
----------------------------- */

app.get(
  "*",
  (_req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);


/* -----------------------------
   START SERVER
----------------------------- */

initDatabase()

  .then(() => {

    app.listen(
      PORT,
      () => {

        if (!OWNER_KEY) {

          console.warn(
            "WARNING: VERIFYIT_OWNER_KEY is not configured. Owner controls will remain unavailable."
          );

        }

        console.log(
          `VerifyIt V1.5 with Lock In Protocol running on port ${PORT}`
        );
      }
    );

  })

  .catch((error) => {

    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
