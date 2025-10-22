const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = 3000;

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Create a users table
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)");
    db.run("INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com')");
    db.run("INSERT INTO users (username, password, email) VALUES ('user', 'password', 'user@example.com')");
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY 1: SQL Injection
app.get('/user/:username', (req, res) => {
    const username = req.params.username;
    // Dangerous: Direct string concatenation in SQL query
    const query = "SELECT * FROM users WHERE username = '" + username + "'";

    db.all(query, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// VULNERABILITY 2: Command Injection
const { exec } = require('child_process');

app.get('/ping/:host', (req, res) => {
    const host = req.params.host;
    // Dangerous: Executing shell command with user input
    exec(`ping -c 3 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// VULNERABILITY 3: Path Traversal
const fs = require('fs');
const path = require('path');

app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    // Dangerous: No validation of file path
    const filePath = path.join(__dirname, 'files', filename);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        res.send(data);
    });
});

// VULNERABILITY 4: XSS (Cross-Site Scripting)
app.get('/search', (req, res) => {
    const query = req.query.q;
    // Dangerous: Reflecting user input without sanitization
    res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
      </body>
    </html>
  `);
});

// VULNERABILITY 5: Hardcoded credentials
const API_KEY = "sk-1234567890abcdefghijklmnop";
const DB_PASSWORD = "MySecretPassword123!";

app.get('/config', (req, res) => {
    res.json({
        apiKey: API_KEY,
        dbPassword: DB_PASSWORD
    });
});

// VULNERABILITY 6: Insecure randomness
app.get('/token', (req, res) => {
    // Dangerous: Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2);
    res.json({ token: token });
});

// VULNERABILITY 7: Regex DoS (ReDoS)
app.post('/validate', (req, res) => {
    const input = req.body.input;
    // Dangerous: Catastrophic backtracking pattern
    const pattern = /^(a+)+$/;

    if (pattern.test(input)) {
        res.send('Valid input');
    } else {
        res.send('Invalid input');
    }
});

// VULNERABILITY 8: Unvalidated redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // Dangerous: Redirecting to user-supplied URL without validation
    res.redirect(url);
});

// VULNERABILITY 9: Information disclosure
app.get('/error', (req, res) => {
    try {
        // Simulate an error
        throw new Error('Database connection failed: host=prod-db-01.internal port=5432 user=admin password=secret123');
    } catch (err) {
        // Dangerous: Exposing full error details to client
        res.status(500).json({
            error: err.message,
            stack: err.stack
        });
    }
});

// VULNERABILITY 10: Missing rate limiting (no code, just absence of protection)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        if (row) {
            res.json({ success: true, message: 'Login successful' });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    });
});

app.get('/', (req, res) => {
    res.send(`
    <h1>Vulnerable Test Application</h1>
    <p>This app contains intentional security vulnerabilities for testing CodeQL.</p>
    <ul>
      <li><a href="/user/admin">SQL Injection Test</a></li>
      <li><a href="/search?q=test">XSS Test</a></li>
      <li><a href="/ping/google.com">Command Injection Test</a></li>
      <li><a href="/download/test.txt">Path Traversal Test</a></li>
      <li><a href="/token">Insecure Random Token</a></li>
      <li><a href="/config">Hardcoded Credentials</a></li>
    </ul>
  `);
});

app.listen(PORT, () => {
    console.log(`Vulnerable app running on http://localhost:${PORT}`);
    console.log('WARNING: This app contains intentional security vulnerabilities!');
    console.log('DO NOT deploy to production or expose to the internet!');
});