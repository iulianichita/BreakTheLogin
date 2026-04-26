import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import userRoutes from './routes/users.js';
import ticketsRoutes from './routes/tickets.js';
import auditLogsRoutes from './routes/audit_logs.js';
import cookieParser from 'cookie-parser';
import db from './database.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use(cookieParser());
app.use('/api/user', userRoutes);
app.use('/api/tickets', ticketsRoutes);
app.use('/api/auditlogs', auditLogsRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/login.html'));
});

app.get('/users', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/users.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/register.html'));
});

app.get('/forgotpassword', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/forgotpassword.html'));
});

app.get('/resetpassword/:token', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/resetpassword.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/profile.html'));
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});