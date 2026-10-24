const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Konfigurasi Koneksi MongoDB Atlas (Ambil dari Environment Variables Vercel)
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://username:password@cluster.mongodb.net/app_ecosystem?retryWrites=true&w=majority';

// Koneksi Database dengan Pola Caching (Optimal untuk Vercel Serverless)
let isConnected = false;
async function connectDB() {
    if (isConnected) return;
    try {
        await mongoose.connect(MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        isConnected = true;
        console.log('Terkoneksi ke MongoDB Atlas.');
    } catch (error) {
        console.error('Koneksi database gagal:', error);
    }
}

// Skema Pengguna (User Schema)
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    preferredLanguage: { type: String, default: 'id' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

const SECRET_KEY = process.env.JWT_SECRET || 'KUNCI_RAHASIA_SUPER_AMAN_UNTUK_PWA_ANDA';

// ================= ROUTES API =================

// Middleware Koneksi DB Otomatis pada Setiap Permintaan API
app.use(async (req, res, next) => {
    await connectDB();
    next();
});

// Endpoint Registrasi
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: 'Semua kolom wajib diisi!' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email sudah terdaftar!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const role = email.includes('admin') ? 'admin' : 'user';

        const newUser = new User({ fullName, email, password: hashedPassword, role });
        await newUser.save();

        res.status(201).json({ message: 'Registrasi berhasil!', user: { fullName, email, role } });
    } catch (err) {
        res.status(500).json({ message: 'Terjadi kesalahan server: ' + err.message });
    }
});

// Endpoint Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email dan password wajib diisi.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Email atau kata sandi salah!' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Email atau kata sandi salah!' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role, name: user.fullName },
            SECRET_KEY,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            name: user.fullName,
            role: user.role,
            preferred_language: user.preferredLanguage || 'id'
        });
    } catch (err) {
        res.status(500).json({ message: 'Terjadi kesalahan server: ' + err.message });
    }
});

// Middleware Validasi Token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token otorisasi tidak ditemukan.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token tidak valid atau kadaluwarsa.' });
        req.user = user;
        next();
    });
};

// Endpoint Metrik Admin
app.get('/api/admin/metrics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Akses ditolak.' });
    }

    try {
        const totalUsers = await User.countDocuments();
        res.json({
            totalUsers: totalUsers,
            totalTransactions: 840,
            activePwas: 5,
            serverStatus: 'Online (MongoDB Atlas)',
            lastUpdate: new Date().toLocaleTimeString('id-ID')
        });
    } catch (err) {
        res.status(500).json({ message: 'Gagal memuat metrik database.' });
    }
});

// Endpoint Profil Pengguna
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('fullName email role createdAt');
        if (!user) return res.status(404).json({ message: 'Profil tidak ditemukan.' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Error server.' });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { fullName } = req.body;
        await User.findByIdAndUpdate(req.user.id, { fullName });
        res.json({ message: 'Profil berhasil diperbarui', name: fullName });
    } catch (err) {
        res.status(500).json({ message: 'Gagal memperbarui profil.' });
    }
});

// ================= SERVER LISTENER =================
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server berjalan di http://localhost:${PORT}`);
    });
}

module.exports = app;