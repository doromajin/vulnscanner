// Safe Node.js patterns — should produce NO JSTAINT-* findings

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const db = require('./db');

const app = express();
app.use(express.json());

// Safe: parseInt sanitizes before use
app.get('/page', async (req, res) => {
    const page = parseInt(req.query.page);
    const rows = await db.query(`SELECT * FROM items LIMIT 10 OFFSET ${page * 10}`);
    res.json(rows);
});

// Safe: static command, no user input
app.get('/status', (req, res) => {
    exec('uptime', (err, stdout) => res.send(stdout));
});

// Safe: fs with a static path
app.get('/static', (req, res) => {
    fs.readFile('/public/index.html', 'utf8', (err, data) => res.send(data));
});

// Safe: parameterized query (user input as 2nd arg, not in SQL string)
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    res.json(rows);
});

// Safe: JSON response (not raw HTML — low XSS risk)
// Note: res.json() with user input is intentionally not flagged (auto-JSON-encodes)
app.get('/echo', (req, res) => {
    const msg = req.query.msg;
    res.json({ message: msg });
});
