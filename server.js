const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const SECRET_KEY = 'KUNCI_RAHASIA_SUPER_AMAN_UNTUK_PWA_ANDA';

// Inisialisasi SQLite Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error membuka database', err.message);
    } else {
        console.log('Terkoneksi ke database SQLite.');
        
        // Tabel Users
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, () => {
            // INJEKSI OTOMATIS: Membuat akun Admin default jika belum ada
            db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
                if (!row) {
                    const hashed = await bcrypt.hash('admin123', 10);
                    db.run(`INSERT INTO users (fullName, email, password, role) VALUES (?, ?, ?, ?)`, 
                    ['Administrator Utama', 'admin@xiancau.com', hashed, 'admin']);
                    console.log('Akun Admin default berhasil dibuat: admin@xiancau.com | Pass: admin123');
                }
            });
        });
        
        // Tabel Log Transaksi
        db.run(`CREATE TABLE IF NOT EXISTS log_transaksi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appName TEXT,
            aktivitas TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Endpoint Registrasi (Otomatis menjadi 'user' biasa)
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (fullName, email, password, role) VALUES (?, ?, ?, 'user')`;
        
        db.run(sql, [fullName, email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ message: 'Email sudah terdaftar.' });
                return res.status(500).json({ message: 'Terjadi kesalahan database.' });
            }
            res.status(201).json({ message: 'Registrasi berhasil! Silakan login.' });
        });
    } catch (error) {
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// Endpoint Login (Mengembalikan Token & Role)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ message: 'Terjadi kesalahan database.' });
        if (!user) return res.status(404).json({ message: 'User tidak ditemukan.' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: 'Password salah.' });

        // JWT token mengikat role spesifik pengguna
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.fullName }, SECRET_KEY, { expiresIn: '7d' });
        
        res.json({ message: 'Login berhasil', token, role: user.role, name: user.fullName });
    });
});

// Middleware Validasi Token Umum
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Middleware Khusus Administrator
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Akses ditolak. Membutuhkan hak Administrator.' });
    next();
};

// Endpoint Panel Dashboard Admin
app.get('/api/admin/metrics', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT COUNT(*) as totalUsers FROM users WHERE role = 'user'`, (err, userRow) => {
        if (err) return res.status(500).json({ message: 'Error membaca database' });
        
        res.json({
            totalUsers: userRow.totalUsers,
            activeApps: 3,
            status: 'Server Database Sinkron & Aman'
        });
    });
});

app.listen(PORT, () => {
    console.log(`Backend API Database berjalan di http://localhost:${PORT}`);
});
