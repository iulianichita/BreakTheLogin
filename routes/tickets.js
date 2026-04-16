import express from 'express';
import db from '../database.js'

const router = express.Router();

const VALID_SEVERITIES = new Set(['LOW', 'MED', 'HIGH']);
const VALID_STATUSES = new Set(['OPEN', 'IN_PROGRESS', 'RESOLVED']);

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}


// Create ticket
router.post('/', (req, res) => {
    const { title, description, severity, status, owner_id } = req.body;

    if (!title || !severity || !status) {
        return badRequest(res, 'title, severity and status are required');
    }
    if (!VALID_SEVERITIES.has(severity)) {
        return badRequest(res, 'severity must be LOW, MED or HIGH');
    }
    if (!VALID_STATUSES.has(status)) {
        return badRequest(res, 'status must be OPEN, IN_PROGRESS or RESOLVED');
    }

    const ownerIdValue = owner_id === undefined || owner_id === null ? null : Number(owner_id);
    if (ownerIdValue !== null && Number.isNaN(ownerIdValue)) {
        return badRequest(res, 'owner_id must be a number');
    }

    const sql = `
        INSERT INTO tickets (title, description, severity, status, owner_id)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.run(sql, [title, description ?? null, severity, status, ownerIdValue], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({
            id: this.lastID,
            title,
            description: description ?? null,
            severity,
            status,
            owner_id: ownerIdValue
        });
    });
});

// Read all tickets
router.get('/', (req, res) => {
    db.all('SELECT * FROM tickets ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Read one ticket
router.get('/:id', (req, res) => {
    const ticketId = Number(req.params.id);

    db.get('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Ticket not found' });
        res.json(row);
    });
});

// Update ticket
router.put('/:id', (req, res) => {
    const ticketId = Number(req.params.id);
    const { title, description, severity, status, owner_id } = req.body;

    const fields = [];
    const values = [];

    if (title !== undefined) {
        fields.push('title = ?');
        values.push(title);
    }
    if (description !== undefined) {
        fields.push('description = ?');
        values.push(description);
    }
    if (severity !== undefined) {
        if (!VALID_SEVERITIES.has(severity)) {
            return badRequest(res, 'severity must be LOW, MED or HIGH');
        }
        fields.push('severity = ?');
        values.push(severity);
    }
    if (status !== undefined) {
        if (!VALID_STATUSES.has(status)) {
            return badRequest(res, 'status must be OPEN, IN_PROGRESS or RESOLVED');
        }
        fields.push('status = ?');
        values.push(status);
    }
    if (owner_id !== undefined) {
        const ownerIdValue = owner_id === null ? null : Number(owner_id);
        if (ownerIdValue !== null && Number.isNaN(ownerIdValue)) {
            return badRequest(res, 'owner_id must be a number or null');
        }
        fields.push('owner_id = ?');
        values.push(ownerIdValue);
    }

    if (fields.length === 0) {
        return badRequest(res, 'No fields provided for update');
    }

    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(ticketId);

    const sql = `UPDATE tickets SET ${fields.join(', ')} WHERE id = ?`;

    db.run(sql, values, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Ticket not found' });
        res.json({ updatedID: ticketId });
    });
});

// Delete ticket
router.delete('/:id', (req, res) => {
    const ticketId = Number(req.params.id);

    db.run('DELETE FROM tickets WHERE id = ?', [ticketId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Ticket not found' });
        res.json({ deletedID: ticketId });
    });
});


export default router;