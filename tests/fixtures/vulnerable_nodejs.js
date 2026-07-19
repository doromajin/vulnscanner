// Node.js vulnerable patterns for scanner testing
// These are INTENTIONALLY VULNERABLE for test purposes only

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');

const app = express();

// CMD-011: child_process with request-derived command
app.post('/run', (req, res) => {
    exec(req.body.command, (err, stdout) => {
        res.send(stdout);
    });
});

// CMD-012: execSync with template literal from request
app.get('/ls', (req, res) => {
    const result = execSync(`ls ${req.query.dir}`);
    res.send(result.toString());
});

// PATH-006: fs.readFile with request-derived path
app.get('/read', (req, res) => {
    fs.readFile(req.query.filename, 'utf8', (err, data) => {
        res.send(data);
    });
});

// PATH-007: fs operation with template literal (dynamic but no explicit req)
app.get('/file', (req, res) => {
    const name = req.params.name;
    fs.readFileSync(`/uploads/${name}`);
});
