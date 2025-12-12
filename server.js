import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import session from "express-session";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
const PORT = 3000;

const CATCI_BASE = "http://localhost:4000";
const CLIENT_ID = "filehost-app";
const CLIENT_SECRET = "super-secret-catci-key";
const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;
const MAX_STORAGE_BYTES = 1024 * 1024 * 1024;

const baseUploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(baseUploadDir)) fs.mkdirSync(baseUploadDir);
const accountsDir = path.join(process.cwd(), "accounts");
if (!fs.existsSync(accountsDir)) fs.mkdirSync(accountsDir);

app.use(express.static("public"));
app.use(express.json());
app.use(
  session({
    secret: "change-this-session-secret",
    resave: false,
    saveUninitialized: false,
  })
);

function safeName(name) {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}
function getUserDir(username) {
  const dir = path.join(baseUploadDir, safeName(username));
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}
function getAccountFile(username) {
  return path.join(accountsDir, safeName(username) + ".json");
}
function getUsedStorageBytes(username) {
  const base = getUserDir(username);
  let total = 0;
  function sumDir(dir) {
    for (const f of fs.readdirSync(dir)) {
      const full = path.join(dir, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) sumDir(full);
      else total += stat.size;
    }
  }
  sumDir(base);
  return total;
}
function getOrCreateAccount(username, email) {
  const file = getAccountFile(username);
  if (!fs.existsSync(file)) {
    const apiKey = crypto.randomBytes(24).toString("hex");
    const acc = {
      username,
      email,
      apiKey,
      usedBytes: 0,
      maxBytes: MAX_STORAGE_BYTES,
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(file, JSON.stringify(acc, null, 2));
    return acc;
  }
  const acc = JSON.parse(fs.readFileSync(file));
  if (!acc.apiKey) {
    acc.apiKey = crypto.randomBytes(24).toString("hex");
    fs.writeFileSync(file, JSON.stringify(acc, null, 2));
  }
  acc.usedBytes = getUsedStorageBytes(username);
  fs.writeFileSync(file, JSON.stringify(acc, null, 2));
  return acc;
}
function resolveUserPath(username, sub = "") {
  const base = getUserDir(username);
  const target = path.join(base, path.normalize(sub));
  if (!target.startsWith(base)) throw new Error("Invalid path");
  return target;
}
function findUserByApiKey(key) {
  const files = fs.readdirSync(accountsDir);
  for (const f of files) {
    const acc = JSON.parse(fs.readFileSync(path.join(accountsDir, f)));
    if (acc.apiKey === key) return acc;
  }
  return null;
}

function authenticate(req, res, next) {
  if (req.session.user) {
    req.authUser = req.session.user.username;
    return next();
  }
  const auth = req.headers.authorization || "";
  const match = auth.match(/^Bearer (.+)$/);
  if (match) {
    const key = match[1];
    const acc = findUserByApiKey(key);
    if (acc) {
      req.authUser = acc.username;
      return next();
    }
  }
  res.status(401).json({ error: "Unauthorized" });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const sub = req.query.path || "";
      const dest = resolveUserPath(req.authUser, sub);
      fs.mkdirSync(dest, { recursive: true });
      cb(null, dest);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => cb(null, Date.now() + "-" + safeName(file.originalname)),
});
const upload = multer({ storage });

app.get("/", (req, res) => {
  if (!req.session.user)
    return res.send(`<h1>FileHost API</h1><a href="/login">Login with Catci</a>`);
  res.sendFile(path.join(process.cwd(), "public", "filemanager.html"));
});

app.get("/login", (req, res) => {
  const state = crypto.randomBytes(8).toString("hex");
  const verifier = crypto.randomBytes(32).toString("hex");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  req.session.state = state;
  req.session.verifier = verifier;
  const url = `${CATCI_BASE}/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&response_type=code&state=${state}&code_challenge=${challenge}`;
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;
  if (state !== req.session.state) return res.status(400).send("Bad state");

  const tokenRes = await fetch(`${CATCI_BASE}/api/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      code_verifier: req.session.verifier,
    }),
  });
  const tokenData = await tokenRes.json();
  const userRes = await fetch(`${CATCI_BASE}/api/oauth/user`, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const user = await userRes.json();

  req.session.user = user;
  getOrCreateAccount(user.username, user.email);
  res.redirect("/");
});

app.get("/logout", async (req, res) => {
  try {
    await fetch(`${CATCI_BASE}/api/logout`, { method: "POST" });
  } catch {}
  req.session.destroy(() => res.redirect("/"));
});

app.get("/api/files", authenticate, (req, res) => {
  const username = req.authUser;
  const subPath = req.query.path || "";
  try {
    const targetDir = resolveUserPath(username, subPath);
    fs.mkdirSync(targetDir, { recursive: true });
    const items = fs.readdirSync(targetDir).map((name) => {
      const full = path.join(targetDir, name);
      const stat = fs.statSync(full);
      const rel = path.relative(getUserDir(username), full);
      return {
        name,
        isDir: stat.isDirectory(),
        size: stat.isFile() ? stat.size : 0,
        mtime: stat.mtime,
        path: rel,
        url: stat.isFile()
          ? `/files/${encodeURIComponent(username)}/${rel
              .split(path.sep)
              .map(encodeURIComponent)
              .join("/")}`
          : null,
      };
    });
    const acc = getOrCreateAccount(username, "");
    acc.usedBytes = getUsedStorageBytes(username);
    fs.writeFileSync(getAccountFile(username), JSON.stringify(acc, null, 2));
    res.json({
      username,
      usedBytes: acc.usedBytes,
      maxBytes: acc.maxBytes,
      path: subPath,
      items,
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/folder", authenticate, (req, res) => {
  const username = req.authUser;
  const { path: sub = "", name } = req.body;
  if (!name) return res.status(400).json({ error: "Missing folder name" });
  try {
    const newPath = resolveUserPath(username, path.join(sub, name));
    fs.mkdirSync(newPath, { recursive: true });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/move", authenticate, (req, res) => {
  const username = req.authUser;
  const { from, to } = req.body;
  if (!from || !to) return res.status(400).json({ error: "Missing fields" });
  try {
    const src = resolveUserPath(username, from);
    const dest = resolveUserPath(username, to);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.renameSync(src, dest);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/upload", authenticate, upload.single("file"), (req, res) => {
  try {
    const username = req.authUser;
    const acc = getOrCreateAccount(username, "");
    const used = getUsedStorageBytes(username);
    if (used > acc.maxBytes) {
      fs.unlinkSync(req.file.path);
      return res
        .status(400)
        .json({ error: "Storage quota exceeded (1 GB limit)" });
    }
    acc.usedBytes = used;
    fs.writeFileSync(getAccountFile(username), JSON.stringify(acc, null, 2));
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/apikey", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  const username = req.session.user.username;
  const acc = getOrCreateAccount(username, req.session.user.email);
  res.json({ apiKey: acc.apiKey });
});

app.use("/files", express.static(baseUploadDir));

app.listen(PORT, () =>
  console.log(`running at http://localhost:${PORT}`)
);