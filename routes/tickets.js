import express from 'express';
import db from '../database.js';
import jwt from 'jsonwebtoken';
import { logAudit } from './audit_helper.js';

const router = express.Router();

const VALID_SEVERITIES = new Set(['LOW', 'MED', 'HIGH']);
const VALID_STATUSES = new Set(['OPEN', 'IN_PROGRESS', 'RESOLVED']);

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}


// Create ticket
router.post('/', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: 'Login required' });

    let decoded;
    try {
        decoded = jwt.verify(token, 'abc');
    } catch (err) {
        console.log('JWT error:', err.message);
        return res.status(401).json({ error: 'Invalid token' });
    }

    if (decoded.manager !== true) {
        return res.status(403).json({ error: 'Only managers can create tickets' });
    }

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

    const ownerIdValue = owner_id === undefined || owner_id === null || owner_id === ''
        ? decoded.userId
        : Number(owner_id);
    if (ownerIdValue !== null && Number.isNaN(ownerIdValue)) {
        return badRequest(res, 'owner_id must be a number');
    }

    const sql = `
        INSERT INTO tickets (title, description, severity, status, owner_id)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.run(sql, [title, description ?? null, severity, status, ownerIdValue], function (err) {
        if (err) return res.status(500).json({ error: err.message });

        logAudit({
            req,
            userId: decoded.userId,
            action: 'TICKET_CREATED',
            resource: 'tickets',
            resourceId: this.lastID
        });

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


// Read tickets
router.get('/', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).json({ error: "Login required" });

    const statusFilterRaw = typeof req.query.status === 'string' ? req.query.status.trim() : '';
    const severityFilterRaw = typeof req.query.severity === 'string' ? req.query.severity.trim() : '';
    const searchFilterRaw = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const statusFilter = statusFilterRaw ? statusFilterRaw.toUpperCase() : null;
    const severityFilter = severityFilterRaw ? severityFilterRaw.toUpperCase() : null;
    const searchFilter = searchFilterRaw || null;

    if (statusFilter && !VALID_STATUSES.has(statusFilter)) {
        return badRequest(res, 'status must be OPEN, IN_PROGRESS or RESOLVED');
    }
    if (severityFilter && !VALID_SEVERITIES.has(severityFilter)) {
        return badRequest(res, 'severity must be LOW, MED or HIGH');
    }

    try {
        const decoded = jwt.verify(token, 'abc');

        if (decoded.manager == true){
            let sql = `
                SELECT
                    tickets.id,
                    tickets.title,
                    tickets.description,
                    tickets.severity,
                    tickets.status,
                    tickets.owner_id,
                    tickets.created_at,
                    tickets.updated_at,
                    users.email AS owner_email
                FROM tickets
                LEFT JOIN users ON users.id = tickets.owner_id
                WHERE 1 = 1
            `;
            const queryParams = [];

            if (statusFilter) {
                sql += ' AND tickets.status = ?';
                queryParams.push(statusFilter);
            }
            if (severityFilter) {
                sql += ' AND tickets.severity = ?';
                queryParams.push(severityFilter);
            }
            if (searchFilter) {
                sql += ' AND (LOWER(tickets.title) LIKE ? OR LOWER(COALESCE(users.email, \"\")) LIKE ?)';
                const searchLike = `%${searchFilter.toLowerCase()}%`;
                queryParams.push(searchLike, searchLike, searchLike);
            }

            sql += ' ORDER BY tickets.created_at DESC';

            db.all(sql, queryParams, async (err, tickets) => {
                if (err) return res.status(500).json({ error: err.message });

                res.json(tickets);
            });
        }
        else {
            let sql = 'SELECT * FROM tickets WHERE owner_id = ?';
            const queryParams = [decoded.userId];

            if (statusFilter) {
                sql += ' AND status = ?';
                queryParams.push(statusFilter);
            }
            if (severityFilter) {
                sql += ' AND severity = ?';
                queryParams.push(severityFilter);
            }
            if (searchFilter) {
                sql += ' AND (LOWER(title) LIKE ?';
                const searchLike = `%${searchFilter.toLowerCase()}%`;
                queryParams.push(searchLike, searchLike);
            }

            sql += ' ORDER BY created_at DESC';

            db.all(sql, queryParams, async (err, tickets) => {
                if (err) return res.status(500).json({ error: err.message });

                res.json(tickets);
            });
        }

    } catch (err) {
        console.log("JWT error:", err.message);
        res.status(401).json({ error: "Invalid token" });
    }
    
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
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Login required' });

    let decoded;
    try {
        decoded = jwt.verify(token, 'abc');
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const ticketId = Number(req.params.id);
    if (Number.isNaN(ticketId)) {
        return badRequest(res, 'id must be a number');
    }

    db.get('SELECT owner_id FROM tickets WHERE id = ?', [ticketId], (findErr, ticketRow) => {
        if (findErr) return res.status(500).json({ error: findErr.message });
        if (!ticketRow) return res.status(404).json({ error: 'Ticket not found' });

        const isManager = decoded.manager === true;
        const isOwner = ticketRow.owner_id === decoded.userId;

        if (!isManager && !isOwner) {
            return res.status(403).json({ error: 'You can only edit your own tickets' });
        }

        if (!isManager && req.body.owner_id !== undefined) {
            return res.status(403).json({ error: 'Only managers can reassign tickets' });
        }

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

        logAudit({
            req,
            userId: decoded.userId,
            action: 'TICKET_UPDATED',
            resource: 'tickets',
            resourceId: ticketId
        });

        res.json({ updatedID: ticketId });
    });
    });
});

// Delete ticket
router.delete('/:id', (req, res) => {
    const ticketId = Number(req.params.id);
    const token = req.cookies.auth_token;

    let actorUserId = null;
    if (token) {
        try {
            const decoded = jwt.verify(token, 'abc');
            actorUserId = decoded.userId;
        } catch (err) {
            actorUserId = null;
        }
    }

    db.run('DELETE FROM tickets WHERE id = ?', [ticketId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Ticket not found' });

        logAudit({
            req,
            userId: actorUserId,
            action: 'TICKET_DELETED',
            resource: 'tickets',
            resourceId: ticketId
        });

        res.json({ deletedID: ticketId });
    });
});


export default router;