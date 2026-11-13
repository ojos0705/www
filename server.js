require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

function getSupabaseAuthClient() {
    const { SUPABASE_URL, SUPABASE_ANON_KEY } = process.env;
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
        throw new Error('Supabase auth is not configured.');
    }

    return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
    });
}

function getSupabaseUserClient(accessToken) {
    const { SUPABASE_URL, SUPABASE_ANON_KEY } = process.env;
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
        throw new Error('Supabase auth is not configured.');
    }

    return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        global: { headers: { Authorization: `Bearer ${accessToken}` } },
        auth: { autoRefreshToken: false, persistSession: false }
    });
}

// ================= ROUTES API =================

function handleSupabaseError(res, error) {
    console.error('Supabase request failed:', error.message);
    return res.status(503).json({ message: 'Layanan akun sedang tidak tersedia. Silakan coba lagi.' });
}

async function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) {
        return res.status(401).json({ message: 'Token otorisasi tidak ditemukan.' });
    }

    try {
        const { data: { user }, error } = await getSupabaseAuthClient().auth.getUser(token);
        if (error || !user) {
            return res.status(401).json({ message: 'Sesi tidak valid atau sudah berakhir.' });
        }

        req.user = user;
        req.accessToken = token;
        next();
    } catch (error) {
        return handleSupabaseError(res, error);
    }
}

// Endpoint Registrasi
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: 'Semua kolom wajib diisi!' });
        }
        if (typeof fullName !== 'string' || typeof email !== 'string' || typeof password !== 'string'
            || fullName.trim().length === 0 || password.length < 6) {
            return res.status(400).json({ message: 'Nama wajib diisi dan kata sandi minimal 6 karakter.' });
        }

        const { data, error } = await getSupabaseAuthClient().auth.signUp({
            email: email.trim().toLowerCase(),
            password,
            options: { data: { full_name: fullName.trim() } }
        });
        if (error) {
            const status = error.status === 400 || error.status === 422 ? 400 : 503;
            return res.status(status).json({ message: status === 400 ? error.message : 'Registrasi gagal. Silakan coba lagi.' });
        }

        return res.status(201).json({
            message: data.session
                ? 'Registrasi berhasil! Silakan login.'
                : 'Registrasi berhasil. Periksa email Anda untuk mengonfirmasi akun.',
            requiresEmailConfirmation: !data.session
        });
    } catch (error) {
        return handleSupabaseError(res, error);
    }
});

// Endpoint Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email dan password wajib diisi.' });
        }

        const { data, error } = await getSupabaseAuthClient().auth.signInWithPassword({
            email: email.trim().toLowerCase(),
            password
        });
        if (error) {
            const status = error.code === 'email_not_confirmed' ? 403 : 401;
            const message = status === 403
                ? 'Email belum dikonfirmasi. Silakan periksa kotak masuk Anda.'
                : 'Email atau kata sandi salah.';
            return res.status(status).json({ message });
        }

        const userClient = getSupabaseUserClient(data.session.access_token);
        const { data: profile, error: profileError } = await userClient
            .from('profiles')
            .select('full_name, role')
            .eq('id', data.user.id)
            .maybeSingle();

        if (profileError) {
            return handleSupabaseError(res, profileError);
        }

        return res.json({
            token: data.session.access_token,
            refreshToken: data.session.refresh_token,
            expiresAt: data.session.expires_at,
            name: profile?.full_name || data.user.user_metadata?.full_name || data.user.email,
            role: profile?.role || 'user'
        });
    } catch (error) {
        return handleSupabaseError(res, error);
    }
});

app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token wajib diisi.' });
    }

    try {
        const { data, error } = await getSupabaseAuthClient().auth.refreshSession({
            refresh_token: refreshToken
        });
        if (error || !data.session) {
            return res.status(401).json({ message: 'Sesi tidak valid atau sudah berakhir. Silakan login kembali.' });
        }

        return res.json({
            token: data.session.access_token,
            refreshToken: data.session.refresh_token,
            expiresAt: data.session.expires_at
        });
    } catch (error) {
        return handleSupabaseError(res, error);
    }
});

// Endpoint Metrik Admin
app.get('/api/admin/metrics', authenticateToken, async (req, res) => {
    try {
        const userClient = getSupabaseUserClient(req.accessToken);
        const { data: profile, error: profileError } = await userClient
            .from('profiles')
            .select('role')
            .eq('id', req.user.id)
            .single();
        if (profileError) return handleSupabaseError(res, profileError);
        if (profile.role !== 'admin') return res.status(403).json({ message: 'Akses ditolak.' });

        const { data: totalUsers, error } = await userClient.rpc('get_landing_admin_user_count');
        if (error) return handleSupabaseError(res, error);

        return res.json({
            totalUsers: totalUsers || 0,
            totalTransactions: 840,
            activePwas: 5,
            serverStatus: 'Online (Supabase)',
            lastUpdate: new Date().toLocaleTimeString('id-ID')
        });
    } catch (error) {
        return handleSupabaseError(res, error);
    }
});

// Endpoint Profil Pengguna
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { data: profile, error } = await getSupabaseUserClient(req.accessToken)
            .from('profiles')
            .select('full_name, role')
            .eq('id', req.user.id)
            .maybeSingle();
        if (error) return handleSupabaseError(res, error);
        if (!profile) return res.status(404).json({ message: 'Profil tidak ditemukan.' });
        return res.json({
            fullName: profile.full_name,
            email: req.user.email,
            role: profile.role
        });
    } catch (error) {
        return handleSupabaseError(res, error);
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { fullName } = req.body;
        if (typeof fullName !== 'string' || !fullName.trim()) {
            return res.status(400).json({ message: 'Nama wajib diisi.' });
        }

        const { error } = await getSupabaseUserClient(req.accessToken)
            .from('profiles')
            .update({ full_name: fullName.trim() })
            .eq('id', req.user.id);
        if (error) return handleSupabaseError(res, error);
        return res.json({ message: 'Profil berhasil diperbarui', name: fullName.trim() });
    } catch (error) {
        return handleSupabaseError(res, error);
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