import express from 'express';
import db from '../database.js'
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import 'dotenv/config';
import { logAudit } from './audit_helper.js';
import { authMiddleware } from './authMiddleware.js';

const router = express.Router();
const saltRounds = 10;
const MAX_FAILED_LOGIN_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const VALID_ROLES = new Set(['USER', 'MANAGER']);
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[.,;:?!*+@#$%\-]).{8,}$/;

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim() !== '';
}

function isValidEmail(email) {
    return isNonEmptyString(email) && EMAIL_REGEX.test(email.trim());
}

const genericResponseInvalidCredentials = 'INVALID_CREDENTIALS';

// Create user
router.post('/register', async (req, res) => {
    const { email, password, role } = req.body;

    if (!isNonEmptyString(email)) {
        return badRequest(res, 'email is required');
    }
    if (!isValidEmail(email)) {
        return badRequest(res, 'email format is invalid');
    }
    if (!isNonEmptyString(password)) {
        return badRequest(res, 'password is required');
    }
    if (!isNonEmptyString(role)) {
        return badRequest(res, 'role is required');
    }

    const roleValue = role.trim().toUpperCase();
    if (!VALID_ROLES.has(roleValue)) {
        return badRequest(res, 'role must be USER or MANAGER');
    }

    if (!PASSWORD_REGEX.test(password)) {
        return badRequest(res, 'password must be at least 8 characters long and include: an uppercase letter, a lowercase letter, a digit and a special character (.,;:?!*+-@#$%)');
    }

    try {
        const hash = await bcrypt.hash(password, saltRounds);

        const sql = 'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)';

        db.run(sql, [email.trim(), hash, roleValue], function (err) {
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
                email: email.trim(),
                role: roleValue
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

    if (!isNonEmptyString(email)) {
        return badRequest(res, 'email is required');
    }
    if (!isValidEmail(email)) {
        return badRequest(res, 'email format is invalid');
    }
    if (!isNonEmptyString(password)) {
        return badRequest(res, 'password is required');
    }
    
    const normalizedEmail = email.trim();
    
    db.get('SELECT * FROM users WHERE email = ?', [normalizedEmail], async (err, user) => {
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

                        req.session.userId = user.id;
                        req.session.manager = user.role === "MANAGER";

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

router.post('/logout', authMiddleware, (req, res) => {
    const genericErrorMessage = 'Invalid data provided';

    db.get('SELECT id, email FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(404).json({ error: genericErrorMessage });

        logAudit({
            req,
            userId: user.id,
            action: 'LOGOUT_SUCCES',
            resource: 'users',
            resourceId: user.id
        });

        req.session.destroy((sessionErr) => {
            if (sessionErr) {
                return res.status(500).json({ error: 'Server error' });
            }
            res.clearCookie('connect.sid');
            return res.json({ message: 'Logout successfully!' });
        });
    });
});

// Read
router.get('/profile', authMiddleware, (req, res) => {
    const genericErrorMessage = 'Invalid data provided';

    db.get('SELECT id, email, role, created_at FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(404).json({ error: genericErrorMessage });

        res.json(user);
    });

});

// Update current user profile
router.put('/profile', authMiddleware, (req, res) => {
    const genericErrorMessage = 'Invalid data provided';
    const { email } = req.body;

    if (!isNonEmptyString(email)) {
        return badRequest(res, 'email is required');
    }
    if (!isValidEmail(email)) {
        return badRequest(res, 'email format is invalid');
    }

    db.run('UPDATE users SET email = ? WHERE id = ?', [email.trim(), req.user.id], function (err) {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (this.changes === 0) return res.status(404).json({ error: genericErrorMessage });

        logAudit({
            req,
            userId: req.user.id,
            action: 'ACCOUNT_UPDATED',
            resource: 'users',
            resourceId: req.user.id
        });

        res.json({ updatedID: req.user.id });
    });
});

// Manager-only user list for assigning tickets
router.get('/assignees', authMiddleware, (req, res) => {
    if (req.user.manager !== true) {
        return res.status(403).json({ error: 'Only managers can view assignees' });
    }

    db.all('SELECT id, email, role FROM users ORDER BY email ASC', [], (err, users) => {
        if (err) return res.status(500).json({ error: 'Server error' });

        res.json(users);
    });
});

// Request forgot password
router.post('/forgotpassword', (req, res) => {
    const { email } = req.body;

    if (!isNonEmptyString(email)) {
        return badRequest(res, 'email is required');
    }
    if (!isValidEmail(email)) {
        return badRequest(res, 'email format is invalid');
    }

    const normalizedEmail = email.trim();

    const genericResponse = {
        message: 'If that email exists, a reset link has been generated.'
    };

    db.get('SELECT id FROM users WHERE email = ?', [normalizedEmail], (err, user) => {
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
    if (!isNonEmptyString(password)) {
        return badRequest(res, 'password is required');
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
                if (!PASSWORD_REGEX.test(password)) {
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
router.delete('/', authMiddleware, (req, res) => {
    const userId = Number(req.user.id);

    if (Number.isNaN(userId)) {
        return badRequest(res, 'id is required and must be a number');
    }

    db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (this.changes === 0) return res.status(404).json({ error: 'Invalid credentials' });

        req.session.destroy((sessionErr) => {
            if (sessionErr) {
                return res.status(500).json({ error: 'Server error' });
            }
            res.clearCookie('connect.sid');
            
            logAudit({
                req,
                userId: null,
                action: 'ACCOUNT_DELETED',
                resource: 'users',
                resourceId: userId
            });

            res.json({ deletedID: userId });
        });
    });
});


export default router;