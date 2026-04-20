import sqlite3 from 'sqlite3';

const dbPath ='./data.sqlite';
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error(err.message);

    console.log('Connected to SQLite.');
});

db.serialize(() => {
    // fara aceasta comanda se pot introduce id-uri care nu exista
    db.run('PRAGMA foreign_keys = ON', (err) => {
        if (err) console.error("Failed to enable FK support:", err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT CHECK(role IN ('ANALYST', 'MANAGER')) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reset_token TEXT,
        reset_token_expires_at DATETIME,
        locked INTEGER DEFAULT 00 CHECK(locked IN (0, 1))
    )`, (err) => { if (err) console.error('users:', err.message); });
        
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT CHECK(severity IN ('LOW', 'MED', 'HIGH')) NOT NULL,
        status TEXT CHECK(status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')) NOT NULL,
        owner_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
            ON DELETE CASCADE 
            ON UPDATE CASCADE
    )`, (err) => { if (err) console.error('tickets:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        resource_id TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE 
            ON UPDATE CASCADE
    )`, (err) => { if (err) console.error('audit_logs:', err.message); });
    
});

export default db;