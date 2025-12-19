import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import session from "express-session";
import fetch from "node-fetch";
import crypto from "crypto";
import archiver from "archiver";
import dotenv from "dotenv";
import { process as processImage } from "./modules/imageProcessor.js";
import { process as processAudio } from "./modules/audioProcessor.js";
import { process as processVideo } from "./modules/videoProcessor.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4042;

const CATCI_BASE = process.env.CATCI_BASE;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const MAX_STORAGE_BYTES = parseInt(process.env.MAX_STORAGE_BYTES) || (10 * 1024 * 1024 * 1024);

const baseUploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(baseUploadDir)) fs.mkdirSync(baseUploadDir);
const accountsDir = path.join(process.cwd(), "accounts");
if (!fs.existsSync(accountsDir)) fs.mkdirSync(accountsDir);
const tempDir = path.join(process.cwd(), "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

// Enable CORS for all origins
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-CATCI-Secret, X-CATCI-Username, X-CATCI-Path");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.static("public"));
app.use(express.json({ limit: '50mb' })); // Increase JSON body limit
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-session-secret",
    resave: false,
    saveUninitialized: false,
  })
);

function safeName(name) {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function isImageFile(filename) {
  const imageExtensions = ['.png', '.jpg', '.jpeg', '.webp', '.avif', '.tiff', '.gif', '.bmp'];
  const ext = path.extname(filename).toLowerCase();
  return imageExtensions.includes(ext);
}

function isAudioFile(filename) {
  const audioExtensions = ['.mp3', '.ogg', '.opus', '.wav', '.flac', '.m4a', '.aac', '.wma', '.aiff'];
  const ext = path.extname(filename).toLowerCase();
  return audioExtensions.includes(ext);
}

function isVideoFile(filename) {
  const videoExtensions = ['.mp4', '.webm', '.mov', '.mkv', '.avi', '.flv', '.wmv', '.ogv', '.m4v', '.3gp', '.ts', '.mts', '.m2ts'];
  const ext = path.extname(filename).toLowerCase();
  return videoExtensions.includes(ext);
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
  const file = getAccountFile(username);d
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

// Generate a 6-character alphanumeric slug
function generateSlug() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let slug = '';
  for (let i = 0; i < 6; i++) {
    slug += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return slug;
}

// Get slug mapping file for a user
function getSlugMapFile(username) {
  return path.join(accountsDir, safeName(username) + ".slugs.json");
}

// Get slug mapping for a user
function getSlugMap(username) {
  const file = getSlugMapFile(username);
  if (!fs.existsSync(file)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

// Save slug mapping for a user
function saveSlugMap(username, slugMap) {
  const file = getSlugMapFile(username);
  fs.writeFileSync(file, JSON.stringify(slugMap, null, 2));
}

// Resolve a file by slug or pretty name to the actual filename
function resolveFileBySlugOrName(username, nameOrSlug) {
  const userDir = getUserDir(username);
  const slugMap = getSlugMap(username);
  
  // Try as slug first (6 chars, alphanumeric)
  if (/^[a-z0-9]{6}$/.test(nameOrSlug) && slugMap[nameOrSlug]) {
    return slugMap[nameOrSlug].timestamp;
  }
  
  // Try as pretty name (original filename)
  // If the input contains a path (subfolders), try resolving that directly
  try {
    const normalized = path.normalize(nameOrSlug);
    if (normalized.includes(path.sep) || normalized.includes('/')) {
      try {
        const full = resolveUserPath(username, normalized);
        if (fs.existsSync(full)) return normalized;
      } catch (e) {
        // fall through to recursive search
      }
    }

    // Recursively search user directory for a matching file.
    // Match exact relative path, basename, or timestamp-style names that end with '-<originalname>'.
    function searchDir(dir) {
      const entries = fs.readdirSync(dir);
      for (const f of entries) {
        const full = path.join(dir, f);
        const stat = fs.statSync(full);
        if (stat.isDirectory()) {
          const found = searchDir(full);
          if (found) return found;
        } else {
          const rel = path.relative(userDir, full);
          if (rel === nameOrSlug || path.basename(rel) === nameOrSlug || rel.endsWith('-' + nameOrSlug)) {
            return rel;
          }
        }
      }
      return null;
    }

    const found = searchDir(userDir);
    if (found) return found;
  } catch (err) {
    // Directory doesn't exist or other error
  }
  
  // Not found
  return null;
}

// Cache cleanup function - removes cached files older than 4 weeks (28 days)
function cleanupOldCache() {
  const FOUR_WEEKS_MS = 28 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  
  if (!fs.existsSync(tempDir)) return;
  
  try {
    const files = fs.readdirSync(tempDir);
    for (const file of files) {
      const filePath = path.join(tempDir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isFile() && now - stat.mtimeMs > FOUR_WEEKS_MS) {
        fs.unlinkSync(filePath);
        console.log(`[cache] Removed old cached file: ${file}`);
      }
    }
  } catch (err) {
    console.error('[cache] Cleanup error:', err.message);
  }
}

// Run cleanup every 24 hours
setInterval(cleanupOldCache, 24 * 60 * 60 * 1000);

// Generate cache key for a file with parameters
function getCacheKey(filePath, params) {
  return crypto
    .createHash('md5')
    .update(filePath + JSON.stringify(params))
    .digest('hex');
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
const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 * 1024, // 10 GB max file size
  }
});

app.get("/", (req, res) => {
  if (req.session.user)
    return res.redirect("/filemanager");
  res.sendFile(path.join(process.cwd(), "public", "home.html"));
});

app.get("/filemanager", (req, res) => {
  if (!req.session.user)
    return res.redirect("/");
  res.sendFile(path.join(process.cwd(), "public", "newfilemanager.html"));
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

app.get("/signup", (req, res) => {
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
  req.session.save(() => {
    res.redirect("/filemanager");
  });
});

app.get("/logout", async (req, res) => {
  try {
    await fetch(`${CATCI_BASE}/api/logout`, { method: "POST" });
  } catch {}
  req.session.destroy(() => res.redirect("/"));
});

// Public file listing endpoint (unauthenticated, requires username in query)
app.get("/api/files-public", (req, res) => {
  const username = req.query.username;
  const subPath = req.query.path || "";
  
  if (!username) {
    return res.status(400).json({ error: "username required" });
  }
  
  try {
    const targetDir = resolveUserPath(username, subPath);
    fs.mkdirSync(targetDir, { recursive: true });
    let slugMap = getSlugMap(username);
    
    const items = fs.readdirSync(targetDir).map((name) => {
      const full = path.join(targetDir, name);
      const stat = fs.statSync(full);
      const rel = path.relative(getUserDir(username), full);
      
      let slug = null;
      let originalName = path.parse(name).name;
      
      if (!stat.isDirectory()) {
        for (const [s, mapping] of Object.entries(slugMap)) {
          const mapped = mapping.timestamp;
          if (
            mapped === rel ||
            path.basename(mapped) === name ||
            mapped.endsWith(path.sep + name) ||
            mapped.endsWith('/' + name)
          ) {
            slug = s;
            originalName = mapping.original;
            break;
          }
        }
        
        if (!slug) {
          slug = generateSlug();
          const match = name.match(/^\d+-(.+)$/);
          const extracted = match ? match[1] : originalName;
          const nameOnly = path.parse(extracted).name;
          const relPath = rel;
          slugMap[slug] = {
            timestamp: relPath,
            original: nameOnly,
            created: new Date().toISOString()
          };
          saveSlugMap(username, slugMap);
          originalName = nameOnly;
        }
      }
      
      return {
        name,
        originalName,
        slug,
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
    
    res.json({
      username,
      path: subPath,
      items,
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/files", authenticate, (req, res) => {
  const username = req.authUser;
  const subPath = req.query.path || "";
  try {
    const targetDir = resolveUserPath(username, subPath);
    fs.mkdirSync(targetDir, { recursive: true });
    let slugMap = getSlugMap(username);
    
    const items = fs.readdirSync(targetDir).map((name) => {
      const full = path.join(targetDir, name);
      const stat = fs.statSync(full);
      const rel = path.relative(getUserDir(username), full);
      
      // Find or create slug for this file
      let slug = null;
      let originalName = path.parse(name).name; // default: filename without extension
      
      if (!stat.isDirectory()) {
        // Look for existing slug (match relative path or basename)
        for (const [s, mapping] of Object.entries(slugMap)) {
          const mapped = mapping.timestamp;
          if (
            mapped === rel ||
            path.basename(mapped) === name ||
            mapped.endsWith(path.sep + name) ||
            mapped.endsWith('/' + name)
          ) {
            slug = s;
            originalName = mapping.original;
            break;
          }
        }
        
        // If no slug found, create one for this file
        if (!slug) {
          slug = generateSlug();
          // Extract original name from timestamp-based filename
          // Format: {timestamp}-{originalname}{ext}
          const match = name.match(/^\d+-(.+)$/);
          const extracted = match ? match[1] : originalName;
          const nameOnly = path.parse(extracted).name;
          // Use the relative path so slugs work for files in subfolders
          const relPath = rel;
          slugMap[slug] = {
            timestamp: relPath,
            original: nameOnly,
            created: new Date().toISOString()
          };
          saveSlugMap(username, slugMap);
          originalName = nameOnly;
        }
      }
      
      return {
        name,
        originalName,
        slug,
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

app.post("/api/rename", authenticate, (req, res) => {
  const username = req.authUser;
  const { path: filePath, newName } = req.body;
  if (!filePath || !newName) return res.status(400).json({ error: "Missing fields" });
  try {
    const src = resolveUserPath(username, filePath);
    const dir = path.dirname(src);
    const dest = path.join(dir, safeName(newName));
    if (fs.existsSync(dest)) {
      return res.status(400).json({ error: "File with that name already exists" });
    }
    fs.renameSync(src, dest);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/delete", authenticate, (req, res) => {
  const username = req.authUser;
  const { path: filePath } = req.body;
  if (!filePath) return res.status(400).json({ error: "Missing file path" });
  try {
    const target = resolveUserPath(username, filePath);
    const stat = fs.statSync(target);
    
    if (stat.isDirectory()) {
      fs.rmSync(target, { recursive: true, force: true });
    } else {
      fs.unlinkSync(target);
    }
    
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
    
    // Generate slug and store mapping
    const slug = generateSlug();
    const slugMap = getSlugMap(username);
    const originalName = path.parse(req.file.originalname).name;
    // Store relative path (includes any upload subfolder) so slugs work for nested files
    const sub = req.query.path || "";
    const relPath = path.join(sub, req.file.filename);

    slugMap[slug] = {
      timestamp: relPath,
      original: originalName,
      created: new Date().toISOString()
    };
    saveSlugMap(username, slugMap);
    
    res.json({ 
      success: true,
      slug,
      timestamp: relPath,
      original: originalName
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Multi-file upload endpoint
app.post("/api/upload-multi", authenticate, upload.array("files"), (req, res) => {
  try {
    const username = req.authUser;
    const acc = getOrCreateAccount(username, "");

    const usedBefore = getUsedStorageBytes(username);
    const totalUploaded = (req.files || []).reduce((s, f) => s + (f.size || 0), 0);

    if (usedBefore + totalUploaded > acc.maxBytes) {
      // Remove files written by multer
      (req.files || []).forEach((f) => {
        try { fs.unlinkSync(f.path); } catch (e) {}
      });
      return res.status(400).json({ error: "Storage quota exceeded" });
    }

    acc.usedBytes = usedBefore + totalUploaded;
    fs.writeFileSync(getAccountFile(username), JSON.stringify(acc, null, 2));

    const slugMap = getSlugMap(username);
    const sub = req.query.path || "";
    const uploaded = [];

    for (const f of (req.files || [])) {
      const slug = generateSlug();
      const originalName = path.parse(f.originalname).name;
      const relPath = path.join(sub, f.filename);
      slugMap[slug] = {
        timestamp: relPath,
        original: originalName,
        created: new Date().toISOString()
      };
      uploaded.push({ slug, timestamp: relPath, original: originalName });
    }

    saveSlugMap(username, slugMap);

    res.json({ success: true, files: uploaded });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CATCI service authentication middleware
function catciAuth(req, res, next) {
  const expected = process.env.CATCI_SECRET || process.env.CATCI_SERVICE_SECRET;
  if (!expected) return res.status(500).json({ error: "CATCI secret not configured" });
  const authHeader = req.headers.authorization || "";
  const bearer = authHeader.match(/^Bearer (.+)$/);
  const secret = req.headers['x-catci-secret'] || (bearer && bearer[1]) || req.query.catci_secret || (req.body && req.body.catci_secret);
  if (!secret) return res.status(401).json({ error: "Missing CATCI secret" });
  if (secret !== expected) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Helper to set req.authUser for routes that reuse existing upload storage logic
function setAuthUserFromCatci(req, res, next) {
  const username = req.query.username || req.headers['x-catci-username'] || (req.body && req.body.username);
  if (!username) return res.status(400).json({ error: "username required" });
  req.authUser = username;
  // allow path via header as multipart won't populate body before multer
  if (!req.query.path && req.headers['x-catci-path']) req.query.path = req.headers['x-catci-path'];
  next();
}

// Create user (idempotent)
app.post('/catci/create-user', catciAuth, (req, res) => {
  const { username, email } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });
  try {
    const acc = getOrCreateAccount(username, email || '');
    res.json({ success: true, username: acc.username, apiKey: acc.apiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CATCI create folder for a user
app.post('/catci/folder', catciAuth, (req, res) => {
  const { username, sub = '', name } = req.body || {};
  if (!username || !name) return res.status(400).json({ error: 'username and name required' });
  try {
    const newPath = resolveUserPath(username, path.join(sub, name));
    fs.mkdirSync(newPath, { recursive: true });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// CATCI single file upload (multipart). Specify username via query/header `username` or query param.
app.post('/catci/upload', catciAuth, setAuthUserFromCatci, upload.single('file'), (req, res) => {
  try {
    const username = req.authUser;
    const acc = getOrCreateAccount(username, '');
    const used = getUsedStorageBytes(username);
    if (used > acc.maxBytes) {
      if (req.file) try { fs.unlinkSync(req.file.path); } catch (e) {}
      return res.status(400).json({ error: 'Storage quota exceeded' });
    }
    // update used bytes
    acc.usedBytes = getUsedStorageBytes(username);
    fs.writeFileSync(getAccountFile(username), JSON.stringify(acc, null, 2));

    // Generate slug and store mapping
    const slug = generateSlug();
    const slugMap = getSlugMap(username);
    const originalName = path.parse(req.file.originalname).name;
    const sub = req.query.path || '';
    const relPath = path.join(sub, req.file.filename);

    slugMap[slug] = {
      timestamp: relPath,
      original: originalName,
      created: new Date().toISOString()
    };
    saveSlugMap(username, slugMap);

    res.json({ success: true, slug, timestamp: relPath, original: originalName });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CATCI multi-file upload
app.post('/catci/upload-multi', catciAuth, setAuthUserFromCatci, upload.array('files'), (req, res) => {
  try {
    const username = req.authUser;
    const acc = getOrCreateAccount(username, '');

    const usedBefore = getUsedStorageBytes(username);
    const totalUploaded = (req.files || []).reduce((s, f) => s + (f.size || 0), 0);

    if (usedBefore + totalUploaded > acc.maxBytes) {
      (req.files || []).forEach((f) => { try { fs.unlinkSync(f.path); } catch (e) {} });
      return res.status(400).json({ error: 'Storage quota exceeded' });
    }

    acc.usedBytes = usedBefore + totalUploaded;
    fs.writeFileSync(getAccountFile(username), JSON.stringify(acc, null, 2));

    const slugMap = getSlugMap(username);
    const sub = req.query.path || '';
    const uploaded = [];

    for (const f of (req.files || [])) {
      const slug = generateSlug();
      const originalName = path.parse(f.originalname).name;
      const relPath = path.join(sub, f.filename);
      slugMap[slug] = { timestamp: relPath, original: originalName, created: new Date().toISOString() };
      uploaded.push({ slug, timestamp: relPath, original: originalName });
    }

    saveSlugMap(username, slugMap);
    res.json({ success: true, files: uploaded });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CATCI file operations: move, rename, delete (require username)
app.post('/catci/move', catciAuth, (req, res) => {
  const { username, from, to } = req.body || {};
  if (!username || !from || !to) return res.status(400).json({ error: 'username, from and to required' });
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

app.post('/catci/rename', catciAuth, (req, res) => {
  const { username, path: filePath, newName } = req.body || {};
  if (!username || !filePath || !newName) return res.status(400).json({ error: 'username, path and newName required' });
  try {
    const src = resolveUserPath(username, filePath);
    const dir = path.dirname(src);
    const dest = path.join(dir, safeName(newName));
    if (fs.existsSync(dest)) return res.status(400).json({ error: 'File with that name already exists' });
    fs.renameSync(src, dest);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/catci/delete', catciAuth, (req, res) => {
  const { username, path: filePath } = req.body || {};
  if (!username || !filePath) return res.status(400).json({ error: 'username and path required' });
  try {
    const target = resolveUserPath(username, filePath);
    const stat = fs.statSync(target);
    if (stat.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
    else fs.unlinkSync(target);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/apikey", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  const username = req.session.user.username;
  const acc = getOrCreateAccount(username, req.session.user.email);
  res.json({ apiKey: acc.apiKey });
});

// Simple file processing endpoint - take username, path, and optional params, return processed file
app.post("/api/package", async (req, res) => {
  try {
    const { username, path: filePath, ...params } = req.body;

    if (!username || !filePath) {
      return res.status(400).json({ error: "username and path required" });
    }

    const fullPath = resolveUserPath(username, filePath);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: "File not found" });
    }

    let processedPath = fullPath;

    // Process image files
    if (isImageFile(fullPath) && Object.keys(params).length > 0) {
      const cacheKey = getCacheKey(fullPath, params);
      const cachedFiles = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (cachedFiles.length > 0) {
        processedPath = path.join(tempDir, cachedFiles[0]);
      } else {
        processedPath = await processImage(fullPath, params, tempDir);
      }
    }
    // Process audio files
    else if (isAudioFile(fullPath) && Object.keys(params).length > 0) {
      const cacheKey = getCacheKey(fullPath, params);
      const cachedFiles = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (cachedFiles.length > 0) {
        processedPath = path.join(tempDir, cachedFiles[0]);
      } else {
        processedPath = await processAudio(fullPath, params, tempDir);
      }
    }
    // Process video files
    else if (isVideoFile(fullPath) && Object.keys(params).length > 0) {
      const cacheKey = getCacheKey(fullPath, params);
      const cachedFiles = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (cachedFiles.length > 0) {
        processedPath = path.join(tempDir, cachedFiles[0]);
      } else {
        processedPath = await processVideo(fullPath, params, tempDir);
      }
    }

    res.sendFile(processedPath);
  } catch (err) {
    console.error('[package] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Dynamic image, audio, and video processing route for /files/<username>/<path> (must come before static serving)
app.get(/^\/files\/([^/]+)\/(.+)$/, async (req, res, next) => {
  try {
    const username = req.params[0];
    let nameOrSlug = req.params[1];
    
    // Resolve the filename from slug or pretty name
    const actualFilename = resolveFileBySlugOrName(username, nameOrSlug);
    
    if (!actualFilename) {
      return res.status(404).json({ error: "File not found" });
    }
    
    const fullPath = resolveUserPath(username, actualFilename);

    // Check if file exists
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: "File not found" });
    }

    // Handle image files
    if (isImageFile(fullPath)) {
      // If no transformation parameters, serve the original file
      if (!req.query.w && !req.query.h && !req.query.s && !req.query.f && !req.query.q) {
        return res.sendFile(fullPath);
      }

      // Check if cached version exists
      const cacheKey = getCacheKey(fullPath, req.query);
      const ext = path.extname(fullPath).slice(1).toLowerCase();
      const cachedPath = path.join(tempDir, `${cacheKey}.*`);
      const files = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (files.length > 0) {
        console.log(`[cache] Image cache hit: ${files[0]}`);
        return res.sendFile(path.join(tempDir, files[0]));
      }

      // Process the image with the provided parameters
      const processedPath = await processImage(fullPath, req.query, tempDir);
      return res.sendFile(processedPath);
    }

    // Handle audio files
    if (isAudioFile(fullPath)) {
      // If no transformation parameters, serve the original file
      if (!req.query.f && !req.query.q) {
        return res.sendFile(fullPath);
      }

      // Check if cached version exists
      const cacheKey = getCacheKey(fullPath, req.query);
      const files = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (files.length > 0) {
        console.log(`[cache] Audio cache hit: ${files[0]}`);
        return res.sendFile(path.join(tempDir, files[0]));
      }

      // Process the audio with the provided parameters
      const processedPath = await processAudio(fullPath, req.query, tempDir);
      return res.sendFile(processedPath);
    }

    // Handle video files
    if (isVideoFile(fullPath)) {
      // If no transformation parameters, serve the original file
      if (!req.query.w && !req.query.h && !req.query.s && !req.query.f && !req.query.q) {
        return res.sendFile(fullPath);
      }

      // Check if cached version exists
      const cacheKey = getCacheKey(fullPath, req.query);
      const files = fs.readdirSync(tempDir).filter(f => f.startsWith(cacheKey));
      
      if (files.length > 0) {
        console.log(`[cache] Video cache hit: ${files[0]}`);
        return res.sendFile(path.join(tempDir, files[0]));
      }

      // Process the video with the provided parameters
      const processedPath = await processVideo(fullPath, req.query, tempDir);
      return res.sendFile(processedPath);
    }

    // Not an image, audio, or video file, let static middleware handle it
    return next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use("/files", express.static(baseUploadDir));

app.listen(PORT, () =>
  console.log(`running at http://localhost:${PORT}`)
);