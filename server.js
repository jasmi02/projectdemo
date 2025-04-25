const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static HTML files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Guest Register
app.post('/register/guest', async (req, res) => {
  const { name, email, password } = req.body; // ✅ Use password from frontend
  const hashedPassword = await bcrypt.hash(password, 10); // ✅ Proper hashing

  db.query(
    'INSERT INTO guests (name, email, password) VALUES (?, ?, ?)',
    [name, email, hashedPassword],
    (err, result) => {
      if (err) {
        console.error('MySQL error:', err);
        return res.status(500).send('Guest registration failed');
      }
      res.redirect('/login.html'); // ✅ Redirect after success
    }
  );
});

// ✅ Host Register
app.post('/register/host', async (req, res) => {
  const { name, email, password, location } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO hosts (name, email, password, location) VALUES (?, ?, ?, ?)',
    [name, email, hashed, location],
    (err, result) => {
      if (err) return res.status(500).send('Host registration failed');
      res.redirect('/login.html');
    }
  );
});

// ✅ Guest Login
app.post('/login/guest', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM guests WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).send('Guest not found');

    const match = await bcrypt.compare(password, results[0].password);
    if (!match) return res.status(401).send('Invalid credentials');

    res.redirect('/index.html'); // ✅ Path should be relative to 'public'
  });
});

// ✅ Host Login
app.post('/login/host', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM hosts WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).send('Host not found');

    const match = await bcrypt.compare(password, results[0].password);
    if (!match) return res.status(401).send('Invalid credentials');

    res.redirect('/host-dashboard.html');
  });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
