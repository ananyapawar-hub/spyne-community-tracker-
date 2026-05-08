// =============================================================
// Spyne Circles Moderator Tracker - server.js
// Stack: Node.js + Express + PostgreSQL + JWT (Authorization hdr)
// =============================================================

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'spyne-secret-2024';

// -------------------------------------------------------------
// Roles
// -------------------------------------------------------------
const ROLES = [
  'admin',
  'tech_team_1', 'tech_team_2',
  'content_team_1', 'content_team_2',
  'product_team_1', 'product_team_2',
  'cs_team_1', 'cs_team_2',
  'branding_team_1', 'branding_team_2'
];

const STAGES = ['Draft', 'In Progress', 'In Review', 'Done'];
const CONTENT_TYPES = ['Post', 'Poll', 'Event', 'Discussion', 'Resource', 'Announcement'];

// -------------------------------------------------------------
// Postgres
// -------------------------------------------------------------
if (!process.env.DATABASE_URL) {
  console.warn('[WARN] DATABASE_URL not set. App will fail to start DB.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS items (
      id UUID PRIMARY KEY,
      title TEXT NOT NULL,
      content_type TEXT,
      category TEXT,
      description TEXT,
      assigned_team TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      due_date DATE,
      stage TEXT DEFAULT 'Draft',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed default admin
  const existing = await pool.query('SELECT 1 FROM users WHERE email = $1', ['admin@spyne.ai']);
  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash('spyne2024', 10);
    await pool.query(
      'INSERT INTO users (id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5)',
      [uuidv4(), 'admin@spyne.ai', 'Admin', hash, 'admin']
    );
    console.log('[init] Seeded default admin: admin@spyne.ai / spyne2024');
  }
}

// -------------------------------------------------------------
// Middleware
// -------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (req.cookies?.token || null);
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// -------------------------------------------------------------
// Auth routes
// -------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });

  const r = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
  if (r.rowCount === 0) return res.status(401).json({ error: 'Invalid login' });
  const u = r.rows[0];
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid login' });

  const token = jwt.sign(
    { id: u.id, email: u.email, name: u.name, role: u.role },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: u.id, email: u.email, name: u.name, role: u.role } });
});

app.get('/api/me', authRequired, async (req, res) => {
  res.json({ user: req.user });
});

// -------------------------------------------------------------
// User management (admin only)
// -------------------------------------------------------------
app.get('/api/users', authRequired, requireRole('admin'), async (req, res) => {
  const r = await pool.query(
    'SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC'
  );
  res.json({ users: r.rows });
});

app.post('/api/users', authRequired, requireRole('admin'), async (req, res) => {
  const { email, name, password, role } = req.body || {};
  if (!email || !name || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });

  const exists = await pool.query('SELECT 1 FROM users WHERE email = $1', [email.toLowerCase().trim()]);
  if (exists.rowCount > 0) return res.status(409).json({ error: 'Email already in use' });

  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  await pool.query(
    'INSERT INTO users (id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5)',
    [id, email.toLowerCase().trim(), name, hash, role]
  );
  res.json({ id });
});

app.patch('/api/users/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { name, role, password } = req.body || {};
  const sets = [];
  const params = [];
  let i = 1;
  if (name) { sets.push(`name = $${i++}`); params.push(name); }
  if (role) {
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    sets.push(`role = $${i++}`); params.push(role);
  }
  if (password) {
    const hash = await bcrypt.hash(password, 10);
    sets.push(`password_hash = $${i++}`); params.push(hash);
  }
  if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${i}`, params);
  res.json({ ok: true });
});

app.delete('/api/users/:id', authRequired, requireRole('admin'), async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "Can't delete yourself" });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// -------------------------------------------------------------
// Items (community content tracker)
// -------------------------------------------------------------
app.get('/api/items', authRequired, async (req, res) => {
  const { mine, stage, team } = req.query;
  const conditions = [];
  const params = [];
  let i = 1;

  if (mine === '1' && req.user.role !== 'admin') {
    conditions.push(`assigned_team = $${i++}`);
    params.push(req.user.role);
  } else if (team) {
    conditions.push(`assigned_team = $${i++}`);
    params.push(team);
  }
  if (stage) {
    conditions.push(`stage = $${i++}`);
    params.push(stage);
  }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  const sql = `
    SELECT i.*, u.name AS created_by_name
    FROM items i
    LEFT JOIN users u ON u.id = i.created_by
    ${where}
    ORDER BY i.created_at DESC
  `;
  const r = await pool.query(sql, params);
  res.json({ items: r.rows });
});

app.post('/api/items', authRequired, async (req, res) => {
  const { title, content_type, category, description, assigned_team, due_date, stage } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Title is required' });
  if (assigned_team && !ROLES.includes(assigned_team)) {
    return res.status(400).json({ error: 'Invalid assigned_team' });
  }
  if (stage && !STAGES.includes(stage)) {
    return res.status(400).json({ error: 'Invalid stage' });
  }
  const id = uuidv4();
  await pool.query(
    `INSERT INTO items
       (id, title, content_type, category, description, assigned_team, created_by, due_date, stage)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [id, title, content_type || null, category || null, description || null,
      assigned_team || null, req.user.id, due_date || null, stage || 'Draft']
  );
  res.json({ id });
});

app.patch('/api/items/:id', authRequired, async (req, res) => {
  // Non-admin team members can only update items assigned to their team
  if (req.user.role !== 'admin') {
    const own = await pool.query('SELECT assigned_team FROM items WHERE id = $1', [req.params.id]);
    if (own.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    if (own.rows[0].assigned_team !== req.user.role) {
      return res.status(403).json({ error: 'Not your item' });
    }
  }

  const allowed = ['title', 'content_type', 'category', 'description', 'assigned_team', 'due_date', 'stage'];
  const sets = [];
  const params = [];
  let i = 1;
  for (const k of allowed) {
    if (k in (req.body || {})) {
      if (k === 'assigned_team' && req.body[k] && !ROLES.includes(req.body[k])) {
        return res.status(400).json({ error: 'Invalid assigned_team' });
      }
      if (k === 'stage' && req.body[k] && !STAGES.includes(req.body[k])) {
        return res.status(400).json({ error: 'Invalid stage' });
      }
      // Non-admin team members cannot reassign items
      if (k === 'assigned_team' && req.user.role !== 'admin') continue;
      sets.push(`${k} = $${i++}`);
      params.push(req.body[k] || null);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update' });
  sets.push(`updated_at = NOW()`);
  params.push(req.params.id);
  await pool.query(`UPDATE items SET ${sets.join(', ')} WHERE id = $${i}`, params);
  res.json({ ok: true });
});

app.delete('/api/items/:id', authRequired, requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM items WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// -------------------------------------------------------------
// Meta
// -------------------------------------------------------------
app.get('/api/meta', authRequired, (req, res) => {
  res.json({ roles: ROLES, stages: STAGES, contentTypes: CONTENT_TYPES });
});

// -------------------------------------------------------------
// Boot
// -------------------------------------------------------------
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`[ready] Spyne Circles Tracker on :${PORT}`);
    });
  })
  .catch(err => {
    console.error('[fatal] DB init failed:', err);
    process.exit(1);
  });
