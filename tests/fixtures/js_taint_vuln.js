// Intentionally vulnerable Node.js patterns for JSTAINT-* rule testing
// These are taint flows where user input is stored in a variable first (indirect)

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const db = require('./db');

const app = express();
app.use(express.json());

// JSTAINT-CMD-001: exec with tainted variable (indirect — not caught by CMD-011)
app.post('/run', (req, res) => {
    const cmd = req.body.command;
    exec(cmd, (err, stdout) => res.send(stdout));
});

// JSTAINT-CMD-002: spawn with tainted variable
app.get('/spawn', (req, res) => {
    const tool = req.query.tool;
    const { spawn } = require('child_process');
    spawn(tool, []);
    res.send('ok');
});

// JSTAINT-SQL-001: db.query with tainted variable
app.get('/users', async (req, res) => {
    const id = req.query.id;
    const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
    res.json(rows);
});

// JSTAINT-PATH-001: fs.readFile with tainted variable
app.get('/read', (req, res) => {
    const filename = req.query.file;
    fs.readFile(filename, 'utf8', (err, data) => res.send(data));
});

// JSTAINT-XSS-001: res.send with tainted variable
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(query);
});

// JSTAINT-EVAL-001: eval with tainted variable
app.post('/calc', (req, res) => {
    const expr = req.body.expression;
    const result = eval(expr);
    res.json({ result });
});

// JSTAINT-SSRF-001: fetch with tainted URL
app.get('/proxy', async (req, res) => {
    const url = req.query.target;
    const response = await fetch(url);
    res.send(await response.text());
});

// Destructuring taint: const { name } = req.body → res.send(name)
app.post('/greet', (req, res) => {
    const { name } = req.body;
    res.send(name);
});

// 2-hop taint: cmd = req.body.x → fullCmd = `ls ${cmd}` → execSync(fullCmd)
app.post('/ls', (req, res) => {
    const dir = req.body.path;
    const fullCmd = `ls ${dir}`;
    const out = execSync(fullCmd);
    res.send(out.toString());
});
