import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_HASH = process.env.ADMIN_CODE_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!ADMIN_HASH || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Set ADMIN_CODE_HASH and a SESSION_SECRET (32+ chars) in the environment.");
  process.exit(1);
}
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const db = new Database(process.env.DB_FILE || path.join(__dirname, "data.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS schedules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, grade TEXT NOT NULL,
 gender TEXT NOT NULL, time TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
 text TEXT NOT NULL, date TEXT NOT NULL
);
`);

const loginLimiter = rateLimit({windowMs: 15*60*1000, limit: 5, standardHeaders: true, legacyHeaders: false,
 message: {error:"محاولات كثيرة. انتظر 15 دقيقة ثم حاول مرة أخرى."}});
const commentLimiter = rateLimit({windowMs: 60*60*1000, limit: 5, standardHeaders: true, legacyHeaders: false});
const allowedGrades = ["رابعة ابتدائي","خامسة ابتدائي","سادسة ابتدائي","أولى إعدادي","تانية إعدادي","تالتة إعدادي","أولى ثانوي","تانية ثانوي","تالتة ثانوي"];
const allowedGenders = ["بنات","أولاد"];
const safeEqual = (a,b) => { const x=Buffer.from(a); const y=Buffer.from(b); return x.length===y.length && crypto.timingSafeEqual(x,y); };
const sign = value => crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
function admin(req,res,next){
  const raw=req.cookies.admin_session||"";
  const [expires,mac]=raw.split(".");
  if(!expires || !mac || Number(expires)<Date.now() || !safeEqual(mac,sign(expires))) return res.status(401).json({error:"سجّل دخول الإدارة أولاً."});
  next();
}
function sameOrigin(req,res,next){
  const origin=req.get("origin");
  if(origin && origin !== `${req.protocol}://${req.get("host")}`) return res.status(403).json({error:"طلب غير مسموح."});
  next();
}
app.use("/api", sameOrigin);
app.get("/api/public",(req,res)=>{
  res.json({schedules:db.prepare("SELECT * FROM schedules ORDER BY id DESC").all(),
    comments:db.prepare("SELECT * FROM comments ORDER BY id DESC LIMIT 100").all()});
});
app.post("/api/comments",commentLimiter,(req,res)=>{
  const name=String(req.body.name||"").trim(), text=String(req.body.text||"").trim();
  if(!name || name.length>45 || !text || text.length>500) return res.status(400).json({error:"راجع الاسم والتعليق (الاسم حتى 45 حرفًا والتعليق حتى 500)."});
  const date=new Intl.DateTimeFormat("ar-EG").format(new Date());
  const result=db.prepare("INSERT INTO comments(name,text,date) VALUES(?,?,?)").run(name,text,date);
  res.status(201).json({id:result.lastInsertRowid});
});
app.post("/api/admin/login",loginLimiter,(req,res)=>{
  const code=String(req.body.code||"");
  const [salt,stored]=ADMIN_HASH.split(":");
  const hash=crypto.scryptSync(code,salt,64).toString("hex");
  if(!stored || !safeEqual(hash,stored)) return res.status(401).json({error:"رمز الإدارة غير صحيح."});
  const expires=String(Date.now()+8*60*60*1000);
  res.cookie("admin_session",expires+"."+sign(expires),{httpOnly:true,sameSite:"strict",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000,path:"/"});
  res.json({ok:true});
});
app.get("/api/admin/data",admin,(req,res)=>res.json({
  schedules:db.prepare("SELECT * FROM schedules ORDER BY id DESC").all(),
  comments:db.prepare("SELECT * FROM comments ORDER BY id DESC").all()
}));
app.post("/api/admin/schedules",admin,(req,res)=>{
  const {grade,gender,time}=req.body;
  if(!allowedGrades.includes(grade)||!allowedGenders.includes(gender)||!String(time||"").trim()||String(time).length>250) return res.status(400).json({error:"بيانات الموعد غير صحيحة."});
  const r=db.prepare("INSERT INTO schedules(grade,gender,time) VALUES(?,?,?)").run(grade,gender,String(time).trim());
  res.status(201).json({id:r.lastInsertRowid});
});
app.put("/api/admin/schedules/:id",admin,(req,res)=>{
  const {grade,gender,time}=req.body;
  if(!allowedGrades.includes(grade)||!allowedGenders.includes(gender)||!String(time||"").trim()||String(time).length>250) return res.status(400).json({error:"بيانات الموعد غير صحيحة."});
  const r=db.prepare("UPDATE schedules SET grade=?,gender=?,time=? WHERE id=?").run(grade,gender,String(time).trim(),req.params.id);
  res.json({updated:r.changes});
});
app.delete("/api/admin/schedules/:id",admin,(req,res)=>res.json({deleted:db.prepare("DELETE FROM schedules WHERE id=?").run(req.params.id).changes}));
app.delete("/api/admin/comments/:id",admin,(req,res)=>res.json({deleted:db.prepare("DELETE FROM comments WHERE id=?").run(req.params.id).changes}));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Website running on port ${PORT}`));
