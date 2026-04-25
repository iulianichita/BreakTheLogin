import express from 'express';
import db from '../database.js'
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { logAudit } from './audit_helper.js';
import bcrypt from 'bcrypt';
import 'dotenv/config';

const router = express.Router();
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const MAX_FAILED_LOGIN_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);

if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is missing. Add JWT_SECRET in .env');
}

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}

const genericResponseInvalidCredentials = 'INVALID_CREDENTIALS';

// Create user
router.post('/register', async (req, res) => {
    const { email, password, role } = req.body;
    const genericErrorMessage = 'Invalid registration data provided';

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[.,;:?!*+@#$%\-]).{8,}$/;
    if (password.length < 8 || !passwordRegex.test(password)) {
        return badRequest(res, 'password must be at least 8 characters long and include: an uppercase letter, a lowercase letter, a digit and a special character (.,;:?!*+-@#$%)');
    }

    try {
        const hash = await bcrypt.hash(password, saltRounds);

        const sql = 'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)';

        db.run(sql, [email, hash, role], function (err) {
            if (err) return res.status(500).json({ error: 'Server error' });

            logAudit({
                req,
                userId: this.lastID,
                action: 'USER_REGISTER',
                resource: 'users',
                resourceId: this.lastID
            });

            res.status(201).json({
                id: this.lastID,
                email,
                role
            });
        });
    } catch (err) {
        return res.status(500).json({ error: 'Encryption error' });
    }
});

// Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    const genericErrorMessage = 'Invalid login data provided';
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(404).json({ error: genericErrorMessage });

        if (user.locked === 1) {
            return res.status(423).json({ error: 'Account locked after too many failed login attempts' });
        }

        try {
            const match = await bcrypt.compare(password, user.password_hash);
            
            if (match) {
                db.run(
                    'UPDATE users SET failed_login_attempts = 0 WHERE id = ?',
                    [user.id],
                    (updateErr) => {
                        if (updateErr) return res.status(500).json({ error: 'Server error' });

                        const payload = { userId: user.id, manager: user.role === "MANAGER"? true : false };
                        const token = jwt.sign(
                            payload,
                            JWT_SECRET,
                            { expiresIn: '10min' }
                        );

                        res.cookie('auth_token', token, {
                            httpOnly: false,            // permite furtul prin XSS (JS poate citi cookie-ul)
                            secure: false,              // merge pe HTTP
                            maxAge: 365 * 24 * 60 * 60 * 1000 // expirare peste 1 an
                        });

                        logAudit({
                            req,
                            userId: user.id,
                            action: 'LOGIN_SUCCESS',
                            resource: 'users',
                            resourceId: user.id
                        });

                        res.json({ success: true, message: "Authentication successful" });
                    }
                );
            } else {
                const nextFailedAttempts = (user.failed_login_attempts || 0) + 1;
                const shouldLock = nextFailedAttempts >= MAX_FAILED_LOGIN_ATTEMPTS;

                db.run(
                    'UPDATE users SET failed_login_attempts = ?, locked = ? WHERE id = ?',
                    [nextFailedAttempts, shouldLock ? 1 : 0, user.id],
                    (updateErr) => {
                        if (updateErr) return res.status(500).json({ error: 'Server error' });

                        logAudit({
                            req,
                            userId: user.id,
                            action: genericResponseInvalidCredentials,
                            resource: 'users',
                            resourceId: user.id
                        });

                        if (shouldLock) {
                            return res.status(423).json({ error: 'Account locked after too many failed login attempts' });
                        }

                        return res.status(401).json({ error: genericErrorMessage });
                    }
                );
            }
        } catch (err) {
            console.error('Error during password comparison:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
    });

});

router.post('/logout', (req, res) => {
    const token = req.cookies.auth_token;

    const genericErrorMessage = 'Invalid data provided';

    if (!token) return res.status(401).json({ error: "Login required" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        db.get('SELECT id, email FROM users WHERE id = ?', [decoded.userId], async (err, user) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (!user) return res.status(404).json({ error: genericErrorMessage });

            res.clearCookie('auth_token', {
                httpOnly: false,
                secure: false,
            });

            logAudit({
                req,
                userId: user.id,
                action: 'LOGOUT_SUCCES',
                resource: 'users',
                resourceId: user.id
            });

            res.json({message: "Logout successfully!"});
        });

    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
});

// Read
router.get('/profile', (req, res) => {
    const token = req.cookies.auth_token;

    const genericErrorMessage = 'Invalid data provided';

    if (!token) return res.status(401).json({ error: "Login required" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        db.get('SELECT id, email, role, created_at FROM users WHERE id = ?', [decoded.userId], async (err, user) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (!user) return res.status(404).json({ error: genericErrorMessage });

            res.json(user);
        });

    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
});

// Update current user profile
router.put('/profile', (req, res) => {
    const token = req.cookies.auth_token;

    const genericErrorMessage = 'Invalid data provided';

    if (!token) return res.status(401).json({ error: 'Login required' });

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const { email } = req.body;

    db.run('UPDATE users SET email = ? WHERE id = ?', [email, decoded.userId], function (err) {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (this.changes === 0) return res.status(404).json({ error: genericErrorMessage });

        logAudit({
            req,
            userId: decoded.userId,
            action: 'ACCOUNT_UPDATED',
            resource: 'users',
            resourceId: decoded.userId
        });

        res.json({ updatedID: decoded.userId });
    });
});

// Manager-only user list for assigning tickets
router.get('/assignees', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: 'Login required' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.manager !== true) {
            return res.status(403).json({ error: 'Only managers can view assignees' });
        }

        db.all('SELECT id, email, role FROM users ORDER BY email ASC', [], (err, users) => {
            if (err) return res.status(500).json({ error: 'Server error' });

            res.json(users);
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Request forgot password
router.post('/forgotpassword', (req, res) => {
    const { email } = req.body;

    const genericResponse = {
        message: 'If that email exists, a reset link has been generated.'
    };

    db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(404).json({error : genericResponse});

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        db.run(
            `UPDATE users
            SET reset_token = ?, reset_token_expires_at = datetime('now', '+15 minutes')
            WHERE id = ?`,
            [tokenHash, user.id],
            function (updateErr) {
                if (updateErr) return res.status(500).json({ error: 'Server error' });

                logAudit({
                    req,
                    userId: user.id,
                    action: 'PASSWORD_RESET_LINK_CREATED',
                    resource: 'users',
                    resourceId: user.id
                });

                res.json({
                    ...genericResponse,
                    resetLink: `${req.protocol}://${req.get('host')}/resetpassword/${resetToken}`
                });
            }
        );
    });
});

// Handle reset password
router.post('/resetpassword/:token', (req, res) => {
    const resetToken = req.params.token;
    const { password } = req.body;

    const genericErrorMessage = 'Invalid credentials';

    if (!resetToken) {
        return badRequest(res, 'reset token is required');
    }

    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    db.get(
        `SELECT id
        FROM users
        WHERE reset_token = ?
        AND reset_token_expires_at IS NOT NULL
        AND datetime(reset_token_expires_at) > datetime('now')`,
        [tokenHash],
        async (err, user) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (!user) return res.status(404).json({ error: genericErrorMessage });

            try {
                const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[.,;:?!*+@#$%\-]).{8,}$/;
                if (password.length < 8 || !passwordRegex.test(password)) {
                    return badRequest(res, 'password must be at least 8 characters long and include: an uppercase letter, a lowercase letter, a digit and a special character (.,;:?!*+-@#$%)');
                }

                const hash = await bcrypt.hash(password, saltRounds);
                db.run(
                    `UPDATE users
                    SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL, failed_login_attempts = 0, locked = 0
                    WHERE id = ?`,
                    [hash, user.id],
                    function (updateErr) {
                        if (updateErr) return res.status(500).json({ error: 'Server error' });
                        if (this.changes === 0) return res.status(404).json({ error: genericErrorMessage });

                        res.clearCookie('auth_token', {
                            httpOnly: false,
                            secure: false,
                        });

                        logAudit({
                            req,
                            userId: user.id,
                            action: 'PASSWORD_RESET_SUCCESS',
                            resource: 'users',
                            resourceId: user.id
                        });

                        res.json({ message: 'Password changed successfully' });
                    }
                );
        
            } catch (err) {
                return res.status(500).json({ error: 'Encryption error' });
            }
    }
    );
});

// Delete user
router.delete('/:id', (req, res) => {
    const userId = Number(req.params.id);
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: 'Login required' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.userId !== userId) {
            return res.status(403).json({ error: 'You can only delete your own account' });
        }

        db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (this.changes === 0) return res.status(404).json({ error: 'Invalid credentials' });

            res.clearCookie('auth_token', {
                httpOnly: false,
                secure: false,
            });

            logAudit({
                req,
                userId: decoded.userId,
                action: 'ACCOUNT_DELETED',
                resource: 'users',
                resourceId: userId
            });

            res.json({ deletedID: userId });
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});


export default router;