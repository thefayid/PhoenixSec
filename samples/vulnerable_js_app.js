/**
 * PhoenixSec Demo — Intentionally Vulnerable Node.js / Express App
 *
 * ⚠️  WARNING: This file is INTENTIONALLY INSECURE for demonstration purposes.
 *     DO NOT deploy this in production. This is a test target for PhoenixSec.
 *
 * Run PhoenixSec scan on this file:
 *     phoenixsec scan samples/vulnerable_js_app.js
 *
 * Vulnerabilities covered:
 *   1. XSS (DOM + Server-side)         CWE-79
 *   2. Hardcoded API Keys / Secrets     CWE-798
 *   3. Command Injection                CWE-78
 *   4. Path Traversal                   CWE-22
 *   5. SSRF                             CWE-918
 *   6. Insecure Deserialization         CWE-502
 *   7. SQL Injection (via template lit) CWE-89
 *   8. Prototype Pollution              CWE-1321
 */

'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { execSync } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 1: Hardcoded API Keys / Secrets (CWE-798)
// PhoenixSec Rule: PSEC-SECRET-001
// ─────────────────────────────────────────────────────────────────────────────
const API_KEY = "sk-abcdef1234567890abcdef1234567890abcdef12";   // OpenAI key
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DATABASE_PASSWORD = "prod_db_password_2024!";
const STRIPE_SECRET = "sk-live-xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const JWT_SECRET = "my_super_secret_jwt_key_do_not_share";


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 2: XSS via innerHTML (CWE-79)
// PhoenixSec Rule: PSEC-XSS-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.get('/greet', (req, res) => {
    const name = req.query.name || 'World';

    // ❌ VULNERABLE: User input injected directly into HTML
    // Attacker: /greet?name=<script>document.cookie</script>
    res.send(`
        <html>
        <body>
            <div id="greeting"></div>
            <script>
                // ❌ VULNERABLE: innerHTML with unsanitized server-rendered data
                document.getElementById('greeting').innerHTML = "Hello, ${name}!";

                // ❌ VULNERABLE: eval with user-controlled data
                var userInput = "${name}";
                eval("console.log('" + userInput + "')");
            </script>
        </body>
        </html>
    `);
});

app.get('/search', (req, res) => {
    const query = req.query.q || '';

    // ❌ VULNERABLE: document.write with user input
    res.send(`
        <html><body>
        <script>
            document.write("<h2>Search results for: ${query}</h2>");
        </script>
        </body></html>
    `);
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 3: SQL Injection via template literals (CWE-89)
// PhoenixSec Rule: PSEC-SQLI-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.get('/users', (req, res) => {
    const userId = req.query.id;

    // ❌ VULNERABLE: Template literal SQL — classic injection point
    const query = `SELECT * FROM users WHERE id = ${userId}`;

    // Would call: db.query(query) — injection exploitable
    res.json({ query_executed: query });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // ❌ VULNERABLE: SQL Injection via string concatenation
    const query = "SELECT * FROM users WHERE username='" + username +
                  "' AND password='" + password + "'";

    res.json({ query: query });
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 4: Command Injection (CWE-78)
// PhoenixSec Rule: PSEC-CMD-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.get('/ping', (req, res) => {
    const host = req.query.host || 'localhost';

    // ❌ VULNERABLE: User input directly in shell command
    // Attacker: /ping?host=localhost; cat /etc/passwd
    try {
        const output = execSync(`ping -c 1 ${host}`, { timeout: 5000 }).toString();
        res.json({ output });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 5: Path Traversal (CWE-22)
// PhoenixSec Rule: PSEC-PT-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.get('/download', (req, res) => {
    const filename = req.query.file || 'report.txt';

    // ❌ VULNERABLE: No path validation
    // Attacker: /download?file=../../../etc/passwd
    const filePath = path.join('/var/app/files', filename);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

app.get('/view', (req, res) => {
    const doc = req.query.doc;

    // ❌ VULNERABLE: readFileSync with user-controlled path
    const content = fs.readFileSync(doc, 'utf8');
    res.send(content);
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 6: SSRF (CWE-918)
// PhoenixSec Rule: PSEC-SSRF-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.get('/fetch', (req, res) => {
    const targetUrl = req.query.url;

    // ❌ VULNERABLE: User-controlled URL — SSRF to internal services
    // Attacker: /fetch?url=http://169.254.169.254/latest/meta-data/
    fetch(targetUrl)
        .then(r => r.text())
        .then(body => res.json({ body: body.substring(0, 500) }))
        .catch(err => res.status(500).json({ error: err.message }));
});

app.get('/proxy', (req, res) => {
    const targetUrl = req.query.url || 'http://example.com';

    // ❌ VULNERABLE: http.get with user input
    http.get(targetUrl, (proxyRes) => {
        let data = '';
        proxyRes.on('data', chunk => { data += chunk; });
        proxyRes.on('end', () => res.send(data.substring(0, 500)));
    }).on('error', err => res.status(500).send(err.message));
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 7: Insecure Deserialization (CWE-502)
// PhoenixSec Rule: PSEC-DESER-JS-001
// ─────────────────────────────────────────────────────────────────────────────
app.post('/deserialize', (req, res) => {
    const { data } = req.body;

    // ❌ VULNERABLE: node-serialize style unserialize with user data
    // This is a known RCE vector via IIFE in serialized objects
    try {
        const obj = require('node-serialize').unserialize(data);
        res.json({ result: obj });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 8: Prototype Pollution (CWE-1321)
// ─────────────────────────────────────────────────────────────────────────────
function mergeObjects(target, source) {
    // ❌ VULNERABLE: Prototype pollution via __proto__
    // Attacker sends: {"__proto__": {"isAdmin": true}}
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = mergeObjects(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/merge', (req, res) => {
    const result = mergeObjects({}, req.body);
    res.json(result);
});


// ─────────────────────────────────────────────────────────────────────────────
// Start Server
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`⚠️  Vulnerable demo app running on port ${PORT}`);
    console.log(`🛡️  Run: phoenixsec scan samples/vulnerable_js_app.js`);
});

module.exports = app;
