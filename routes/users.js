import express from 'express';
import db from '../database.js'
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { logAudit } from './audit_helper.js';

const router = express.Router();

const VALID_ROLES = new Set(['ANALYST', 'MANAGER']);

function normalizeLocked(value) {
    if (value === undefined) return undefined;
    if (value === true || value === 1 || value === '1') return 1;
    if (value === false || value === 0 || value === '0') return 0;
    return null;
}

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}


// Create user
router.post('/register', (req, res) => {
    const { email, password, role, locked } = req.body;
    const normalizedLocked = normalizeLocked(locked ?? 0);

    if (!email || !password || !role) {
        return badRequest(res, 'email, password and role are required');
    }
    if (!VALID_ROLES.has(role)) {
        return badRequest(res, 'role must be ANALYST or MANAGER');
    }
    if (normalizedLocked === null) {
        return badRequest(res, 'locked must be 0/1 or boolean');
    }

    const sql = 'INSERT INTO users (email, password_hash, role, locked) VALUES (?, ?, ?, ?)';

    db.run(sql, [email, password, role, normalizedLocked], function (err) {
        if (err) return res.status(500).json({ error: err.message });

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
            role,
            locked: normalizedLocked
        });
    });
});

// Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) {
            logAudit({
                req,
                userId: null,
                action: 'LOGIN_FAILED_USER_NOT_FOUND',
                resource: 'users',
                resourceId: email ?? null
            });

            return res.status(404).json({ error: 'User not found' });
        }

        const match = password == user.password_hash;
        
        if (match) {
            const payload = { userId: user.id, manager: user.role === "MANAGER"? true : false };
            const token = jwt.sign(
                payload, 
                'abc', 
                { expiresIn: '30d' }
            );

            res.cookie('auth_token', token, { 
                httpOnly: false,            // permite furtul prin XSS (JS poate citi cookie-ul)
                secure: false,              // merge pe HTTP
                maxAge: 365 * 24 * 60 * 60  // expirare peste 1 an
            });

            logAudit({
                req,
                userId: user.id,
                action: 'LOGIN_SUCCESS',
                resource: 'users',
                resourceId: user.id
            });

            res.json({ success: true, message: "Authentication successful" });
        } else {
            logAudit({
                req,
                userId: user.id,
                action: 'LOGIN_FAILED_WRONG_PASSWORD',
                resource: 'users',
                resourceId: user.id
            });

            res.status(401).json({ error: 'Incorrect password' });
        }
    });

});

router.post('logout', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: "Login required" });

    try {
        const decoded = jwt.verify(token, 'abc');

        db.get('SELECT id, email  FROM users WHERE id = ?', [decoded.userId], async (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!user) return res.status(404).json({ error: 'User not found' });

            res.clearCookie('auth_token', {
                httpOnly: false,
                secure: false,
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

    if (!token) return res.status(401).json({ error: "Login required" });

    try {
        const decoded = jwt.verify(token, 'abc');

        db.get('SELECT id, email, role, created_at FROM users WHERE id = ?', [decoded.userId], async (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!user) return res.status(404).json({ error: 'User not found' });

            res.json(user);
        });

    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
});

// Update current user profile
router.put('/profile', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: 'Login required' });

    let decoded;
    try {
        decoded = jwt.verify(token, 'abc');
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const { email } = req.body;

    if (!email) {
        return badRequest(res, 'email cannot be empty');
    }

    const sql = `UPDATE users SET email = ? WHERE id = ?`;

    db.run(sql, [email, decoded.userId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });

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
        const decoded = jwt.verify(token, 'abc');

        if (decoded.manager !== true) {
            return res.status(403).json({ error: 'Only managers can view assignees' });
        }

        db.all('SELECT id, email, role FROM users ORDER BY email ASC', [], (err, users) => {
            if (err) return res.status(500).json({ error: err.message });

            res.json(users);
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Request reset password
router.post('/forgotpassword', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return badRequest(res, 'email is required');
    }

    const genericResponse = {
        message: 'If that email exists, a reset link has been generated.'
    };

    db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            logAudit({
                req,
                userId: null,
                action: 'PASSWORD_RESET_REQUESTED_UNKNOWN_EMAIL',
                resource: 'users',
                resourceId: email
            });

            return res.json(genericResponse);
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        db.run(
            `UPDATE users
            SET reset_token = ?, reset_token_expires_at = datetime('now', '+15 minutes')
            WHERE id = ?`,
            [tokenHash, user.id],
            function (updateErr) {
                if (updateErr) return res.status(500).json({ error: updateErr.message });

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

    if (!resetToken) {
        return badRequest(res, 'reset token is required');
    }
    if (!password) {
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
        (err, user) => {
            if (err) return res.status(500).json({ error: err.message });

            if (!user) {
                logAudit({
                    req,
                    userId: null,
                    action: 'PASSWORD_RESET_FAILED_INVALID_OR_EXPIRED_TOKEN',
                    resource: 'users',
                    resourceId: tokenHash.slice(0, 12)
                });

                return res.status(400).json({ error: 'Invalid or expired reset token' });
            }

            db.run(
                `UPDATE users
                SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL
                WHERE id = ?`,
                [password, user.id],
                function (updateErr) {
                    if (updateErr) return res.status(500).json({ error: updateErr.message });
                    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });

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
        }
    );
});

// Delete user
router.delete('/:id', (req, res) => {
    const userId = Number(req.params.id);

    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: 'Login required' });

    try {
        const decoded = jwt.verify(token, 'abc');

        if (decoded.userId !== userId) {
            return res.status(403).json({ error: 'You can only delete your own account' });
        }

        db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'User not found' });

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