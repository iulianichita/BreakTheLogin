import express from 'express';
import db from '../database.js'
import jwt from 'jsonwebtoken';

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
    const { email, password_hash, role, locked } = req.body;
    const normalizedLocked = normalizeLocked(locked ?? 0);

    if (!email || !password_hash || !role) {
        return badRequest(res, 'email, password_hash and role are required');
    }
    if (!VALID_ROLES.has(role)) {
        return badRequest(res, 'role must be ANALYST or MANAGER');
    }
    if (normalizedLocked === null) {
        return badRequest(res, 'locked must be 0/1 or boolean');
    }

    const sql = 'INSERT INTO users (email, password_hash, role, locked) VALUES (?, ?, ?, ?)';

    db.run(sql, [email, password_hash, role, normalizedLocked], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({
            id: this.lastID,
            email,
            role,
            locked: normalizedLocked
        });
    });
});

// // Read all users
// router.get('/', (req, res) => {
//     db.all('SELECT id, email, role, created_at, locked FROM users ORDER BY id DESC', [], (err, rows) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(rows);
//     });
// });

// // Read one user
// router.get('/:id', (req, res) => {
//     const userId = Number(req.params.id);

//     db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
//         if (err) return res.status(500).json({ error: err.message });
//         if (!row) return res.status(404).json({ error: 'User not found' });
//         res.json(row);
//     });
// });

// Login
router.post('/login', (req, res) => {
    const { email, password_hash } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const match = password_hash == user.password_hash;
        
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

            res.json({ success: true, message: "Authentication successful" });
        } else {
            res.status(401).json({ error: 'Incorrect password' });
        }
    });

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

    const { email, password_hash } = req.body;
    const fields = [];
    const values = [];

    if (email !== undefined) {
        if (!email) {
            return badRequest(res, 'email cannot be empty');
        }
        fields.push('email = ?');
        values.push(email);
    }

    if (password_hash !== undefined) {
        if (!password_hash) {
            return badRequest(res, 'password_hash cannot be empty');
        }
        fields.push('password_hash = ?');
        values.push(password_hash);
    }

    if (fields.length === 0) {
        return badRequest(res, 'No fields provided for update');
    }

    values.push(decoded.userId);
    const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;

    db.run(sql, values, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
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

// Update user
router.put('/:id', (req, res) => {
    const userId = Number(req.params.id);
    const { email, password_hash, role, locked } = req.body;

    const fields = [];
    const values = [];

    if (email !== undefined) {
        fields.push('email = ?');
        values.push(email);
    }
    if (password_hash !== undefined) {
        fields.push('password_hash = ?');
        values.push(password_hash);
    }
    if (role !== undefined) {
        if (!VALID_ROLES.has(role)) {
            return badRequest(res, 'role must be ANALYST or MANAGER');
        }
        fields.push('role = ?');
        values.push(role);
    }
    if (locked !== undefined) {
        const normalizedLocked = normalizeLocked(locked);
        if (normalizedLocked === null) {
            return badRequest(res, 'locked must be 0/1 or boolean');
        }
        fields.push('locked = ?');
        values.push(normalizedLocked);
    }

    if (fields.length === 0) {
        return badRequest(res, 'No fields provided for update');
    }

    values.push(userId);
    const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;

    db.run(sql, values, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ updatedID: userId });
    });
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
            res.json({ deletedID: userId });
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});


export default router;