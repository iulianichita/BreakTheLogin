import express from 'express';
import db from '../database.js';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const router = express.Router();

// Read all audit logs
router.get('/', (req, res) => {
    const token = req.cookies.auth_token;
    
    if (!token) return res.status(401).json({ error: 'Login required' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.manager !== true) {
            return res.status(403).json({ error: 'Only managers can view audit logs' });
        }

        db.all('SELECT * FROM audit_logs ORDER BY id DESC', [], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            res.json(rows);
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});


export default router;