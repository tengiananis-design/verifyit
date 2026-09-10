import express from "express";
import crypto from "crypto";
import Database from "better-sqlite3";
import QRCode from "qrcode";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const db = new Database(process.env.DB_PATH || path.join(__dirname, "verifyit.db"));

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS businesses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id INTEGER NOT NULL,
  brand TEXT NOT NULL,
  product_name TEXT NOT NULL,
  batch TEXT DEFAULT '',
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  verification_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);
CREATE TABLE IF NOT EXISTS verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER,
  code TEXT NOT NULL,
  result TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  FOREIGN KEY (product_id) REFERENCES products(id)
);
`);

app.use(express.json({ limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));

function now() { return new Date().toISOString(); }
function makeCode() {
  let code;
  do { code = crypto.randomBytes(8).toString("hex").toUpperCase().match(/.{1,4}/g).join("-"); }
  while (db.prepare("SELECT 1 FROM products WHERE code=?").get(code));
  return code;
}
function tokenFor(business) {
  return jwt.sign({ id: business.id, email: business.email }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) throw new Error();
    req.business = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Please log in." }); }
}
function publicProduct(p) {
  return { brand:p.brand, productName:p.product_name, batch:p.batch, code:p.code, status:p.status, verificationCount:p.verification_count, createdAt:p.created_at };
}

app.post("/api/register", async (req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name||!email||!password||password.length<8) return res.status(400).json({error:"Name, email and a password of at least 8 characters are required."});
  try {
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare("INSERT INTO businesses(name,email,password_hash,created_at) VALUES(?,?,?,?)").run(String(name).trim(),String(email).trim().toLowerCase(),hash,now());
    const b=db.prepare("SELECT id,name,email FROM businesses WHERE id=?").get(info.lastInsertRowid);
    res.status(201).json({token:tokenFor(b),business:b});
  } catch { res.status(409).json({error:"That email is already registered."}); }
});

app.post("/api/login", async (req,res)=>{
  const {email,password}=req.body||{};
  const b=db.prepare("SELECT * FROM businesses WHERE email=?").get(String(email||"").trim().toLowerCase());
  if(!b || !(await bcrypt.compare(String(password||""),b.password_hash))) return res.status(401).json({error:"Invalid email or password."});
  res.json({token:tokenFor(b),business:{id:b.id,name:b.name,email:b.email}});
});

app.get("/api/me",auth,(req,res)=>{
  const b=db.prepare("SELECT id,name,email,created_at FROM businesses WHERE id=?").get(req.business.id);
  res.json(b);
});

app.post("/api/products",auth,(req,res)=>{
  const {brand,productName,batch}=req.body||{};
  if(!brand||!productName) return res.status(400).json({error:"Brand and product name are required."});
  const code=makeCode(), createdAt=now();
  const info=db.prepare("INSERT INTO products(business_id,brand,product_name,batch,code,created_at) VALUES(?,?,?,?,?,?)")
    .run(req.business.id,String(brand).trim(),String(productName).trim(),String(batch||"").trim(),code,createdAt);
  const p=db.prepare("SELECT * FROM products WHERE id=?").get(info.lastInsertRowid);
  res.status(201).json(publicProduct(p));
});

app.get("/api/products",auth,(req,res)=>{
  const rows=db.prepare("SELECT * FROM products WHERE business_id=? ORDER BY id DESC").all(req.business.id);
  res.json(rows.map(publicProduct));
});

app.patch("/api/products/:code/status",auth,(req,res)=>{
  const status=req.body?.status;
  if(!["active","disabled","recalled"].includes(status)) return res.status(400).json({error:"Invalid status."});
  const result=db.prepare("UPDATE products SET status=? WHERE code=? AND business_id=?").run(status,req.params.code,req.business.id);
  if(!result.changes) return res.status(404).json({error:"Product not found."});
  res.json({ok:true});
});

app.get("/api/products/:code/qr",auth,async(req,res)=>{
  const p=db.prepare("SELECT * FROM products WHERE code=? AND business_id=?").get(req.params.code,req.business.id);
  if(!p) return res.status(404).json({error:"Product not found."});
  const base=process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
  const verifyUrl=`${base}/?verify=${encodeURIComponent(p.code)}#verify`;
  const data=await QRCode.toDataURL(verifyUrl,{margin:2,width:600});
  res.json({url:verifyUrl,data});
});

app.get("/api/verify/:code",(req,res)=>{
  const code=String(req.params.code||"").trim().toUpperCase();
  const p=db.prepare("SELECT * FROM products WHERE code=?").get(code);
  if(!p){
    db.prepare("INSERT INTO verifications(code,result,checked_at) VALUES(?,?,?)").run(code,"not_verified",now());
    return res.json({result:"not_verified",message:"This code is not registered in the VerifyIt database."});
  }
  const result=p.status==="active" ? (p.verification_count>=5 ? "warning":"authentic") : "warning";
  const message=p.status==="active"
    ? (result==="warning" ? "This code is registered, but it has unusually high verification activity. Check the item with the seller or manufacturer." : "The code matches a registered product record.")
    : `This product record is marked ${p.status}.`;
  db.prepare("UPDATE products SET verification_count=verification_count+1 WHERE id=?").run(p.id);
  db.prepare("INSERT INTO verifications(product_id,code,result,checked_at) VALUES(?,?,?,?)").run(p.id,code,result,now());
  const fresh=db.prepare("SELECT * FROM products WHERE id=?").get(p.id);
  res.json({result,product:publicProduct(fresh),message});
});

app.get("/api/stats",auth,(req,res)=>{
  const products=db.prepare("SELECT COUNT(*) c FROM products WHERE business_id=?").get(req.business.id).c;
  const checks=db.prepare("SELECT COUNT(*) c FROM verifications v JOIN products p ON p.id=v.product_id WHERE p.business_id=?").get(req.business.id).c;
  const warnings=db.prepare("SELECT COUNT(*) c FROM verifications v JOIN products p ON p.id=v.product_id WHERE p.business_id=? AND v.result='warning'").get(req.business.id).c;
  res.json({products,checks,warnings});
});

app.get("*",(_req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`VerifyIt V1.1 running on port ${PORT}`));
