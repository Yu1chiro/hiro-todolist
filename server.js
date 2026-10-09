require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool, types } = require('pg');

// Kolom DATE (OID 1082) dikembalikan apa adanya sebagai string 'YYYY-MM-DD' (tanpa konversi zona waktu)
types.setTypeParser(1082, (v) => v);

const { APP_PIN, JWT_SECRET, DATABASE_URL } = process.env;
if (!APP_PIN || !JWT_SECRET || !DATABASE_URL) {
  console.error('Isi APP_PIN, JWT_SECRET, DATABASE_URL di .env');
  process.exit(1);
}

const app = express();
const PORT = 3000;
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const CATS = ['Work', 'Study', 'Productive', 'Hobby'];
const TYPES = ['Low', 'Medium', 'Urgent'];

// ---------- Middleware keamanan (manual, tanpa helmet) ----------
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
  });
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Pembatasan percobaan PIN (brute-force protection)
const fails = new Map();

function auth(req, res, next) {
  try {
    jwt.verify(req.cookies.token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// Tolak request mutasi yang bukan JSON (mitigasi CSRF tambahan selain SameSite=Strict)
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !req.is('application/json'))
    return res.status(415).json({ error: 'Content-Type harus JSON' });
  next();
});

// ---------- Auth ----------
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip;
  const rec = fails.get(ip) || { n: 0, until: 0 };
  if (rec.until > Date.now()) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi 15 menit lagi' });

  const hash = (v) => crypto.createHash('sha256').update(String(v)).digest();
  if (!crypto.timingSafeEqual(hash(req.body.pin || ''), hash(APP_PIN))) {
    rec.n++;
    if (rec.n >= 5) { rec.until = Date.now() + 15 * 60 * 1000; rec.n = 0; }
    fails.set(ip, rec);
    return res.status(401).json({ error: 'PIN salah' });
  }
  fails.delete(ip);
  const token = jwt.sign({ ok: 1 }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: false, maxAge: 7 * 864e5 }).json({ ok: true });
});
app.get('/api/auth/me', auth, (req, res) => res.json({ ok: true }));
app.post('/api/auth/logout', (req, res) => res.clearCookie('token').json({ ok: true }));

// ---------- Validasi ----------
function validate(b) {
  const name = String(b.name || '').trim();
  const due = String(b.due_at || '').slice(0, 10);
  if (!name || name.length > 150) return { error: 'Nama task wajib diisi (maks 150 karakter)' };
  const dt = /^\d{4}-\d{2}-\d{2}$/.test(due) ? new Date(due + 'T00:00:00Z') : null;
  if (!dt || isNaN(dt) || dt.toISOString().slice(0, 10) !== due) return { error: 'Tanggal tidak valid' };
  if (!CATS.includes(b.category)) return { error: 'Kategori tidak valid' };
  if (!TYPES.includes(b.type)) return { error: 'Tipe tidak valid' };
  const description = String(b.description || '')
    .slice(0, 20000)
    .replace(/<(script|iframe|object|embed|style)[\s\S]*?<\/\1>/gi, '')
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*')/gi, '');
  return { v: [name, due, b.category, b.type, description] };
}
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const idOk = (req, res, next) => (Number.isInteger(+req.params.id) ? next() : res.status(400).json({ error: 'ID tidak valid' }));

// ---------- CRUD Task ----------
app.get('/api/tasks', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tasks ORDER BY due_at ASC');
  res.json(rows);
}));

app.post('/api/tasks', auth, wrap(async (req, res) => {
  const { v, error } = validate(req.body);
  if (error) return res.status(400).json({ error });
  const { rows } = await pool.query(
    'INSERT INTO tasks (name, due_at, category, type, description) VALUES ($1,$2,$3,$4,$5) RETURNING *', v);
  res.status(201).json(rows[0]);
}));

app.put('/api/tasks/:id', auth, idOk, wrap(async (req, res) => {
  const { v, error } = validate(req.body);
  if (error) return res.status(400).json({ error });
  const { rows } = await pool.query(
    'UPDATE tasks SET name=$1, due_at=$2, category=$3, type=$4, description=$5, updated_at=NOW() WHERE id=$6 RETURNING *',
    [...v, req.params.id]);
  rows[0] ? res.json(rows[0]) : res.status(404).json({ error: 'Task tidak ditemukan' });
}));

app.patch('/api/tasks/:id/toggle', auth, idOk, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE tasks SET is_done = NOT is_done,
       completed_at = CASE WHEN is_done THEN NULL ELSE NOW() END, updated_at = NOW()
     WHERE id=$1 RETURNING *`, [req.params.id]);
  rows[0] ? res.json(rows[0]) : res.status(404).json({ error: 'Task tidak ditemukan' });
}));

app.delete('/api/tasks/:id', auth, idOk, wrap(async (req, res) => {
  const r = await pool.query('DELETE FROM tasks WHERE id=$1', [req.params.id]);
  r.rowCount ? res.json({ ok: true }) : res.status(404).json({ error: 'Task tidak ditemukan' });
}));

// ---------- Route View (SPA) ----------
const indexFile = path.join(__dirname, 'public', 'index.html');
['/', '/statistic', '/calendar'].forEach((p) => app.get(p, (req, res) => res.sendFile(indexFile)));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((req, res) => res.redirect('/'));

app.listen(PORT, () => console.log(`Hiro Garden Todo jalan di http://localhost:${PORT}`));