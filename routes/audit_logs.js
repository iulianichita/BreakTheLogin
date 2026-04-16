import express from 'express';
import db from '../database.js'

const router = express.Router();

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}


// Create audit log
router.post('/', (req, res) => {
    const { user_id, action, resource, resource_id, ip_address } = req.body;

    if (!action) {
        return badRequest(res, 'action is required');
    }

    const userIdValue = user_id === undefined || user_id === null ? null : Number(user_id);
    if (userIdValue !== null && Number.isNaN(userIdValue)) {
        return badRequest(res, 'user_id must be a number');
    }

    const sql = `
        INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.run(sql, [userIdValue, action, resource ?? null, resource_id ?? null, ip_address ?? req.ip], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({
            id: this.lastID,
            user_id: userIdValue,
            action,
            resource: resource ?? null,
            resource_id: resource_id ?? null,
            ip_address: ip_address ?? req.ip
        });
    });
});

// Read all audit logs
router.get('/', (req, res) => {
    db.all('SELECT * FROM audit_logs ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Read one audit log
router.get('//:id(\\d+)', (req, res) => {
    const logId = Number(req.params.id);

    db.get('SELECT * FROM audit_logs WHERE id = ?', [logId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Audit log not found' });
        res.json(row);
    });
});

// Update audit log
router.put('/:id(\\d+)', (req, res) => {
    const logId = Number(req.params.id);
    const { user_id, action, resource, resource_id, ip_address } = req.body;

    const fields = [];
    const values = [];

    if (user_id !== undefined) {
        const userIdValue = user_id === null ? null : Number(user_id);
        if (userIdValue !== null && Number.isNaN(userIdValue)) {
            return badRequest(res, 'user_id must be a number or null');
        }
        fields.push('user_id = ?');
        values.push(userIdValue);
    }
    if (action !== undefined) {
        fields.push('action = ?');
        values.push(action);
    }
    if (resource !== undefined) {
        fields.push('resource = ?');
        values.push(resource);
    }
    if (resource_id !== undefined) {
        fields.push('resource_id = ?');
        values.push(resource_id);
    }
    if (ip_address !== undefined) {
        fields.push('ip_address = ?');
        values.push(ip_address);
    }

    if (fields.length === 0) {
        return badRequest(res, 'No fields provided for update');
    }

    fields.push('timestamp = CURRENT_TIMESTAMP');
    values.push(logId);

    const sql = `UPDATE audit_logs SET ${fields.join(', ')} WHERE id = ?`;

    db.run(sql, values, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Audit log not found' });
        res.json({ updatedID: logId });
    });
});

// Delete audit log
router.delete('/:id(\\d+)', (req, res) => {
    const logId = Number(req.params.id);

    db.run('DELETE FROM audit_logs WHERE id = ?', [logId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Audit log not found' });
        res.json({ deletedID: logId });
    });
});


export default router;