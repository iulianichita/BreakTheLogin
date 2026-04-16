import express from 'express';
import db from '../database.js'

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
router.post('/', (req, res) => {
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

// Read all users
router.get('/', (req, res) => {
    db.all('SELECT id, email, role, created_at, locked FROM users ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Read one user
router.get('/:id(\\d+)', (req, res) => {
    const userId = Number(req.params.id);

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json(row);
    });
});

// Update user
router.put('/:id(\\d+)', (req, res) => {
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
router.delete('/:id(\\d+)', (req, res) => {
    const userId = Number(req.params.id);

    db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ deletedID: userId });
    });
});


export default router;