const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./user_data.db');

app.use(helmet());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Create table
const createTable = `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    surname TEXT NOT NULL,
    age INTEGER NOT NULL
);`;
db.run(createTable);

const BASIC_AUTH_USER = 'admin';
const BASIC_AUTH_PASS = 'password';

function requireBasicAuth(req, res, next) {
    const auth = req.headers['authorization'];
    if (!auth || !auth.startsWith('Basic ')) {
        res.set('WWW-Authenticate', 'Basic realm="API User"');
        return res.status(401).send('Authentication required.');
    }
    const base64 = auth.split(' ')[1];
    let [user, pass] = Buffer.from(base64, 'base64').toString().split(':');
    if (user !== BASIC_AUTH_USER || pass !== BASIC_AUTH_PASS) {
        res.set('WWW-Authenticate', 'Basic realm="API User"');
        return res.status(401).send('Invalid credentials.');
    }
    return next();
}

app.use('/api', requireBasicAuth);

// Serve html page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Handle form POST
app.post('/submit', (req, res) => {
    const { name, surname, age } = req.body;
    const safeName = String(name).replace(/[^a-zA-Z\s'-]/g, '').trim();
    const safeSurname = String(surname).replace(/[^a-zA-Z\s'-]/g, '').trim();
    const safeAge = Number(age);
    if (!safeName || !safeSurname || isNaN(safeAge) || safeAge < 1 || safeAge > 120) {
        return res.status(400).send('Invalid input.');
    }
    db.run('INSERT INTO users (name, surname, age) VALUES (?, ?, ?)', [safeName, safeSurname, safeAge], (err) => {
        if (err) return res.status(500).send('Database error.');
        res.redirect('/');
    });
});

// REST API endpoint to list all users
app.get('/api/users', (req, res) => {
    db.all('SELECT id, name, surname, age FROM users', [], (err, rows) => {
        if (err) return res.status(500).json({error: 'Database error.'});
        res.json(rows);
    });
});

// REST API endpoint to get total user count
app.get('/api/users/count', (req, res) => {
    db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
        if (err) return res.status(500).json({error: 'Database error.'});
        res.json({ count: row.count });
    });
});

// REST API endpoint to delete a user by id
app.delete('/api/users/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'Invalid user id.' });
    }
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({error: 'Database error.'});
        if (this.changes === 0) {
            return res.status(404).json({error: 'User not found.'});
        }
        res.json({ success: true });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
