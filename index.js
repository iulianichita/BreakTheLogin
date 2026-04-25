import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import session from 'express-session';
import userRoutes from './routes/users.js';
import ticketsRoutes from './routes/tickets.js';
import auditLogsRoutes from './routes/audit_logs.js';
import cookieParser from 'cookie-parser';
import db from './database.js';
import { authMiddleware } from './routes/authMiddleware.js';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));
app.use('/api/user', userRoutes);
app.use('/api/tickets', ticketsRoutes);
app.use('/api/auditlogs', auditLogsRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/register.html'));
});

app.get('/forgotpassword', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/forgotpassword.html'));
});

app.get('/resetpassword/:token', (req, res) => {
    const rawToken = req.params.token;

    // Reset tokens are generated as 32 random bytes in hex format.
    if (!/^[a-f0-9]{64}$/i.test(rawToken)) {
        return res.status(404).send('Invalid or expired reset link.');
    }

    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    db.get(
        `SELECT id
        FROM users
        WHERE reset_token = ?
        AND reset_token_expires_at IS NOT NULL
        AND datetime(reset_token_expires_at) > datetime('now')`,
        [tokenHash],
        (err, user) => {
            if (err) return res.status(500).send('Could not validate reset link.');
            if (!user) return res.status(404).send('Invalid or expired reset link.');

            res.sendFile(path.join(__dirname, './templates/resetpassword.html'));
        }
    );
});

app.get('/profile', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, './templates/profile.html'));
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});