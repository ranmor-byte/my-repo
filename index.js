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

// Serve html page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
    db.all('SELECT name, surname, age FROM users', [], (err, rows) => {
        if (err) return res.status(500).json({error: 'Database error.'});
        res.json(rows);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
