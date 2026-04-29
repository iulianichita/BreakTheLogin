import express from 'express';
import db from '../database.js';
import 'dotenv/config';
import { authMiddleware } from './authMiddleware.js';

const router = express.Router();

// Read all audit logs
router.get('/', authMiddleware, (req, res) => {
    if (req.user.manager !== true) {
        return res.status(403).json({ error: 'Only managers can view audit logs' });
    }

    db.all('SELECT * FROM audit_logs ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        res.json(rows);
    });
});


export default router;