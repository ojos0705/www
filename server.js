const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server berjalan di http://localhost:${PORT}`);
    });
}
const SECRET_KEY = process.env.JWT_SECRET || 'KUNCI_RAHASIA_SUPER_AMAN_UNTUK_PWA_ANDA';

// Di Vercel Serverless, gunakan folder sementara /tmp untuk membaca/menulis file sqlite
const dbPath = process.env.VERCEL 
  ? path.join('/tmp', 'database.sqlite') 
  : path.join(__dirname, 'database.sqlite');

// Inisialisasi SQLite Database
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error membuka database:', err.message);
    } else {
        console.log('Terkoneksi ke database SQLite pada:', dbPath);
        initDatabase();
    }
});

// Inisialisasi Tabel & Admin
function initDatabase() {
    db.serialize(() => {
        // Tabel Users
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) return console.error('Error buat tabel users:', err.message);

            // Cek & Buat Admin Default
            db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
                if (!err && !row) {
                    try {
                        const hashed = await bcrypt.hash('admin123', 10);
                        db.run(`INSERT INTO users (fullName, email, password, role) VALUES (?, ?, ?, ?)`, 
                        ['Administrator Utama', 'admin@xiancau.com', hashed, 'admin']);
                        console.log('Akun Admin default berhasil dibuat.');
                    } catch (e) {
                        console.error('Gagal membuat admin default:', e);
                    }
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
    });
}

// Endpoint Registrasi
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (fullName, email, password, role) VALUES (?, ?, ?, 'user')`;
        
        db.run(sql, [fullName, email, hashedPassword], function(err) {
            if (err) {
                if (err.message && err.message.includes('UNIQUE')) {
                    return res.status(400).json({ message: 'Email sudah terdaftar.' });
                }
                return res.status(500).json({ message: 'Terjadi kesalahan database: ' + err.message });
            }
            res.status(201).json({ message: 'Registrasi berhasil! Silakan login.' });
        });
    } catch (error) {
        res.status(500).json({ message: 'Terjadi kesalahan server: ' + error.message });
    }
});

// Endpoint Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }
    
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ message: 'Terjadi kesalahan database: ' + err.message });
        if (!user) return res.status(404).json({ message: 'User tidak ditemukan.' });

        try {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) return res.status(401).json({ message: 'Password salah.' });

            const token = jwt.sign(
                { id: user.id, email: user.email, role: user.role, name: user.fullName }, 
                SECRET_KEY, 
                { expiresIn: '7d' }
            );
            
            res.json({ message: 'Login berhasil', token, role: user.role, name: user.fullName });
        } catch (bcryptErr) {
            res.status(500).json({ message: 'Gagal memverifikasi password.' });
        }
    });
});

// Middleware Validasi Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token tidak ditemukan.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token tidak valid atau kadaluwarsa.' });
        req.user = user;
        next();
    });
};

// Middleware Khusus Administrator
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Akses ditolak. Membutuhkan hak Administrator.' });
    }
    next();
};

// Endpoint Panel Dashboard Admin
app.get('/api/admin/metrics', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT COUNT(*) as totalUsers FROM users WHERE role = 'user'`, (err, userRow) => {
        if (err) return res.status(500).json({ message: 'Error membaca database: ' + err.message });
        
        res.json({
            totalUsers: userRow ? userRow.totalUsers : 0,
            activeApps: 3,
            status: 'Server Database Sinkron & Aman'
        });
    });
});

app.get('/api/profile', authenticateToken, (req, res) => {
    db.get(`SELECT id, fullName, email, role, createdAt FROM users WHERE id = ?`, [req.user.id], (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'Data pengguna tidak ditemukan.' });
        res.json(row);
    });
});

// Jalankan app.listen HANYA jika dijalankan di Localhost (Bukan Vercel Serverless)
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Backend API Database berjalan di http://localhost:${PORT}`);
    });
}

module.exports = app;