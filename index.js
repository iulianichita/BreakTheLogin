import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import userRoutes from './routes/users.js';
import ticketsRoutes from './routes/tickets.js';
import auditLogsRoutes from './routes/audit_logs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use('/api/user', userRoutes);
app.use('/api/tickets', ticketsRoutes);
app.use('/api/auditlogs', auditLogsRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './templates/login.html'));
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});