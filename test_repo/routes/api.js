const express = require('express');
const router = express.Router();
const fs = require('fs');
const { exec } = require('child_process');

// Exposed endpoints
router.get("/users", (req, res) => {
    const filter = req.query.filter;
    res.json({ users: [] });
});

router.post("/execute", (req, res) => {
    const script = req.body.script;
    // Dangerous execution sink + source in express
    exec(script, (err, stdout, stderr) => {
        res.send(stdout);
    });
});

router.get("/download", (req, res) => {
    const target = req.query.file;
    fs.readFile(`/var/app/storage/${target}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

module.exports = router;
