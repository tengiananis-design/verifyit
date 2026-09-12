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

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";

const OWNER_KEY =
  process.env.VERIFYIT_OWNER_KEY || "";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
  process.exit(1);
}

if (!process.env.VERIFYIT_OWNER_KEY) {
  console.warn(
    "WARNING: VERIFYIT_OWNER_KEY is not configured. Owner controls will remain unavailable."
  );
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* =========================================================
   DATABASE SETUP
========================================================= */

async function initDatabase() {
  /*
    IMPORTANT:

    Each SQL operation is executed separately.

    PostgreSQL/pg does not allow the previous combination
    of multiple commands plus a parameterized prepared
    statement.
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
    ========================================================
    VERIFYIT LOCK IN PROTOCOL TABLES
    ========================================================
  */

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

  /*
    Create the default lockdown setting only if it
    does not already exist.

    IMPORTANT:
    ON CONFLICT DO NOTHING means an existing lockdown
    state is never overwritten during a restart/deploy.
  */

  await pool.query(
    `
      INSERT INTO system_settings
        (
          setting_name,
          setting_value,
          updated_at
        )
      VALUES
        (
          $1,
          $2,
          $3
        )
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

/* =========================================================
   GENERAL HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

/* =========================================================
   LOCK IN PROTOCOL
   GET CURRENT LOCKDOWN STATE
========================================================= */

async function getLockdownState() {
  const result = await pool.query(`
    SELECT setting_value
    FROM system_settings
    WHERE setting_name = 'verifyit_lockdown'
    LIMIT 1
  `);

  if (!result.rows[0]) {
    throw new Error(
      "VerifyIt lockdown setting does not exist."
    );
  }

  return result.rows[0].setting_value === "true";
}

/* =========================================================
   LOCK IN PROTOCOL
   SET LOCKDOWN STATE
========================================================= */

async function setLockdownState(locked) {
  await pool.query(
    `
      INSERT INTO system_settings
        (
          setting_name,
          setting_value,
          updated_at
        )
      VALUES
        (
          $1,
          $2,
          $3
        )
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

/* =========================================================
   LOCK IN PROTOCOL
   OWNER AUDIT LOG
========================================================= */

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
        VALUES
          (
            $1,
            $2,
            $3
          )
      `,
      [
        action,
        result,
        now()
      ]
    );
  } catch (error) {
    /*
      Audit failure must never expose the owner key
      or crash the application.
    */

    console.error(
      "Owner audit log failed:",
      error.message
    );
  }
}

/* =========================================================
   LOCK IN PROTOCOL
   SAFE OWNER KEY COMPARISON
========================================================= */

function safeOwnerKeyCompare(
  providedKey
) {
  if (!OWNER_KEY) {
    return false;
  }

  if (
    typeof providedKey !== "string" ||
    providedKey.length === 0
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

/* =========================================================
   LOCK IN PROTOCOL
   OWNER AUTHENTICATION
========================================================= */

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

  /*
    Owner key is supplied through a request header.

    Example:

    x-verifyit-owner-key: YOUR_SECRET
  */

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
      error: "Unauthorized."
    });
  }

  req.isVerifyItOwner = true;

  next();
}

/* =========================================================
   LOCK IN PROTOCOL
   SERVER-SIDE LOCKDOWN MIDDLEWARE
========================================================= */

async function lockdownMiddleware(
  req,
  res,
  next
) {
  /*
    Owner requests are allowed.

    The owner routes are registered before this
    middleware, but this also protects against
    future owner-authenticated routes.
  */

  if (req.isVerifyItOwner) {
    return next();
  }

  let locked;

  try {
    locked =
      await getLockdownState();
  } catch (error) {
    /*
      FAIL-SAFE:

      If the server cannot determine the lockdown
      state, normal protected operations are blocked.

      This prevents a database/settings failure from
      accidentally opening VerifyIt.
    */

    console.error(
      "Unable to determine VerifyIt lockdown state:",
      error.message
    );

    return res.status(503).json({
      success: false,
      locked: true,
      error:
        "VerifyIt is temporarily unavailable."
    });
  }

  if (locked) {
    return res.status(503).json({
      success: false,
      locked: true,
      error:
        "VerifyIt is currently under lockdown."
    });
  }

  next();
}

/* =========================================================
   PRODUCT CODE GENERATOR
========================================================= */

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
        `
          SELECT 1
          FROM products
          WHERE code = $1
        `,
        [code]
      )
    ).rowCount
  );

  return code;
}

/* =========================================================
   BUSINESS TOKEN
========================================================= */

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

/* =========================================================
   BUSINESS AUTHENTICATION
========================================================= */

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

/* =========================================================
   PUBLIC PRODUCT FORMAT
========================================================= */

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

/* =========================================================
   IMAGE VALIDATION
========================================================= */

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

    The frontend compresses images before sending them.
  */

  if (
    imageData.length >
    1500000
  ) {
    return false;
  }

  return true;
}

/* =========================================================
   EXPRESS
========================================================= */

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

/* =========================================================
   HEALTH CHECK
   ALWAYS AVAILABLE
========================================================= */

app.get(
  "/api/health",
  async (_req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      let locked = null;

      try {
        locked =
          await getLockdownState();
      } catch {
        locked = null;
      }

      res.json({
        ok: true,
        service: "VerifyIt",
        version: "1.5.0",
        database:
          "postgresql",
        lockdown:
          locked === null
            ? "unknown"
            : locked
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

/* =========================================================
   OWNER — LOCKDOWN STATUS
========================================================= */

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
      console.error(
        "Owner status error:",
        error
      );

      res.status(503).json({
        success: false,
        error:
          "Unable to read lockdown state."
      });
    }
  }
);

/* =========================================================
   OWNER — ACTIVATE LOCKDOWN
========================================================= */

app.post(
  "/api/owner/lockdown",
  ownerAuth,
  async (_req, res) => {
    try {
      const currentState =
        await getLockdownState();

      if (currentState) {
        await writeOwnerAudit(
          "LOCKDOWN",
          "ALREADY_LOCKED"
        );

        return res.json({
          success: true,
          locked: true,
          message:
            "VerifyIt is already under lockdown."
        });
      }

      await setLockdownState(
        true
      );

      await writeOwnerAudit(
        "LOCKDOWN",
        "ACTIVATED"
      );

      res.json({
        success: true,
        locked: true,
        message:
          "VerifyIt lockdown activated."
      });
    } catch (error) {
      console.error(
        "Lockdown activation failed:",
        error
      );

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

/* =========================================================
   OWNER — RESTORE VERIFYIT
========================================================= */

app.post(
  "/api/owner/unlock",
  ownerAuth,
  async (_req, res) => {
    try {
      const currentState =
        await getLockdownState();

      if (!currentState) {
        await writeOwnerAudit(
          "UNLOCK",
          "ALREADY_UNLOCKED"
        );

        return res.json({
          success: true,
          locked: false,
          message:
            "VerifyIt is already operational."
        });
      }

      await setLockdownState(
        false
      );

      await writeOwnerAudit(
        "UNLOCK",
        "DEACTIVATED"
      );

      res.json({
        success: true,
        locked: false,
        message:
          "VerifyIt restored to normal operation."
      });
    } catch (error) {
      console.error(
        "Unlock failed:",
        error
      );

      await writeOwnerAudit(
        "UNLOCK",
        "FAILED"
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to restore VerifyIt."
      });
    }
  }
);

/* =========================================================
   OWNER — AUDIT LOG
========================================================= */

app.get(
  "/api/owner/audit-log",
  ownerAuth,
  async (_req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            id,
            action,
            result,
            created_at
          FROM owner_audit_log
          ORDER BY id DESC
          LIMIT 100
        `);

      res.json({
        success: true,
        logs:
          result.rows
      });
    } catch (error) {
      console.error(
        "Audit log error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Unable to load audit log."
      });
    }
  }
);

/* =========================================================
   SERVER-SIDE LOCKDOWN STARTS HERE
=========================================================

   Everything below this point is protected by
   the Lock In Protocol.

   When lockdown = true:

   - Registration blocked
   - Login blocked
   - Business APIs blocked
   - Product APIs blocked
   - Product image APIs blocked
   - QR APIs blocked
   - Public verification blocked
   - Statistics blocked

   Owner routes above remain available.
========================================================= */

app.use(
  "/api",
  lockdownMiddleware
);

/* =========================================================
   BUSINESS REGISTRATION
========================================================= */

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
            (
              $1,
              $2,
              $3,
              $4
            )
            RETURNING
              id,
              name,
              email
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
          tokenFor(business),

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

/* =========================================================
   BUSINESS LOGIN
========================================================= */

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
            String(
              email || ""
            )
              .trim()
              .toLowerCase()
          ]
        );

      const business =
        result.rows[0];

      if (
        !business ||
        !(
          await bcrypt.compare(
            String(
              password || ""
            ),
            business.password_hash
          )
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      res.json({
        token:
          tokenFor(business),

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

/* =========================================================
   CURRENT BUSINESS
========================================================= */

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

      if (
        !result.rows[0]
      ) {
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

/* =========================================================
   CREATE PRODUCT
========================================================= */

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
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7
            )
            RETURNING *
          `,
          [
            req.business.id,

            String(brand)
              .trim(),

            String(
              productName
            ).trim(),

            String(
              batch || ""
            ).trim(),

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

/* =========================================================
   LIST PRODUCTS
========================================================= */

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

/* =========================================================
   GET PRODUCT IMAGE
========================================================= */

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
          product.image_data ||
          ""
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

/* =========================================================
   REPLACE PRODUCT IMAGE
========================================================= */

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

      if (
        !result.rowCount
      ) {
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

/* =========================================================
   DELETE PRODUCT
========================================================= */

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

      if (
        !result.rowCount
      ) {
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

/* =========================================================
   CHANGE PRODUCT STATUS
========================================================= */

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

      if (
        !result.rowCount
      ) {
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

/* =========================================================
   GENERATE QR CODE
========================================================= */

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

/* =========================================================
   PUBLIC PRODUCT VERIFICATION
========================================================= */

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
            (
              $1,
              $2,
              $3
            )
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
          (
            $1,
            $2,
            $3,
            $4
          )
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

/* =========================================================
   BUSINESS STATISTICS
========================================================= */

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
   FRONTEND
========================================================= */

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

/* =========================================================
   START SERVER
========================================================= */

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      () => {
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
