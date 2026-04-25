import express from 'express';
import db from '../database.js';
import { logAudit } from './audit_helper.js';
import { authMiddleware } from './authMiddleware.js';

const router = express.Router();

const VALID_SEVERITIES = new Set(['LOW', 'MED', 'HIGH']);
const VALID_STATUSES = new Set(['OPEN', 'IN_PROGRESS', 'RESOLVED']);

function badRequest(res, message) {
    return res.status(400).json({ error: message });
}

router.use(authMiddleware);

// Create ticket
router.post('/', (req, res) => {
    if (req.user.manager !== true) {
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
        ? req.user.id
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
            userId: req.user.id,
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

    if (req.user.manager === true) {
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
            sql += ' AND (LOWER(tickets.title) LIKE ? OR LOWER(COALESCE(users.email, "")) LIKE ?)';
            const searchLike = `%${searchFilter.toLowerCase()}%`;
            queryParams.push(searchLike, searchLike);
        }

        sql += ' ORDER BY tickets.created_at DESC';

        db.all(sql, queryParams, (err, tickets) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(tickets);
        });
        return;
    }

    let sql = 'SELECT * FROM tickets WHERE owner_id = ?';
    const queryParams = [req.user.id];

    if (statusFilter) {
        sql += ' AND status = ?';
        queryParams.push(statusFilter);
    }
    if (severityFilter) {
        sql += ' AND severity = ?';
        queryParams.push(severityFilter);
    }
    if (searchFilter) {
        sql += ' AND LOWER(title) LIKE ?';
        queryParams.push(`%${searchFilter.toLowerCase()}%`);
    }

    sql += ' ORDER BY created_at DESC';

    db.all(sql, queryParams, (err, tickets) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(tickets);
    });
});

// Read one ticket
router.get('/:id', (req, res) => {
    const ticketId = Number(req.params.id);
    if (Number.isNaN(ticketId)) {
        return badRequest(res, 'id must be a number');
    }

    db.get('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Ticket not found' });

        const isManager = req.user.manager === true;
        const isOwner = row.owner_id === req.user.id;
        if (!isManager && !isOwner) {
            return res.status(403).json({ error: 'You can only view your own tickets' });
        }

        res.json(row);
    });
});

// Update ticket
router.put('/:id', (req, res) => {
    const ticketId = Number(req.params.id);
    if (Number.isNaN(ticketId)) {
        return badRequest(res, 'id must be a number');
    }

    db.get('SELECT owner_id FROM tickets WHERE id = ?', [ticketId], (findErr, ticketRow) => {
        if (findErr) return res.status(500).json({ error: findErr.message });
        if (!ticketRow) return res.status(404).json({ error: 'Ticket not found' });

        const isManager = req.user.manager === true;
        const isOwner = ticketRow.owner_id === req.user.id;

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
                userId: req.user.id,
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
    if (Number.isNaN(ticketId)) {
        return badRequest(res, 'id must be a number');
    }

    db.get('SELECT owner_id FROM tickets WHERE id = ?', [ticketId], (findErr, ticketRow) => {
        if (findErr) return res.status(500).json({ error: findErr.message });
        if (!ticketRow) return res.status(404).json({ error: 'Ticket not found' });

        const isManager = req.user.manager === true;
        const isOwner = ticketRow.owner_id === req.user.id;
        if (!isManager && !isOwner) {
            return res.status(403).json({ error: 'You can only delete your own tickets' });
        }

        db.run('DELETE FROM tickets WHERE id = ?', [ticketId], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'Ticket not found' });

            logAudit({
                req,
                userId: req.user.id,
                action: 'TICKET_DELETED',
                resource: 'tickets',
                resourceId: ticketId
            });

            res.json({ deletedID: ticketId });
        });
    });
});

export default router;
