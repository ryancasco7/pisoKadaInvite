const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('./pisokada.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        
        // Create tables
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                referral_code TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_id INTEGER NOT NULL,
                visitor_ip TEXT NOT NULL,
                clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                earned INTEGER DEFAULT 1,
                FOREIGN KEY (referrer_id) REFERENCES users(id)
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS earnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL DEFAULT 0,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )`);

            db.run(`CREATE INDEX IF NOT EXISTS idx_ip_address ON users(ip_address)`);
            db.run(`CREATE INDEX IF NOT EXISTS idx_referral_code ON users(referral_code)`);
        });
    }
});

// Helper function to get client IP
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.headers['x-real-ip'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null);
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token.' });
        }
        req.user = user;
        next();
    });
}

// Check IP address limit (max 3 accounts per IP)
app.post('/api/check-ip', async (req, res) => {
    const ip = getClientIP(req);
    
    db.get('SELECT COUNT(*) as count FROM users WHERE ip_address = ?', [ip], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (row.count >= 3) {
            return res.status(400).json({ 
                error: 'Maximum 3 accounts allowed per device/IP address',
                canRegister: false 
            });
        }
        
        res.json({ canRegister: true, currentCount: row.count });
    });
});

// Register new user
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    const ip = getClientIP(req);

    // Check IP limit
    db.get('SELECT COUNT(*) as count FROM users WHERE ip_address = ?', [ip], async (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (row.count >= 3) {
            return res.status(400).json({ 
                error: 'Maximum 3 accounts allowed per device/IP address' 
            });
        }

        // Check if username or email already exists
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (user) {
                return res.status(400).json({ error: 'Username or email already exists' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            const referralCode = uuidv4().substring(0, 8).toUpperCase();

            // Create user
            db.run('INSERT INTO users (username, email, password, referral_code, ip_address) VALUES (?, ?, ?, ?, ?)',
                [username, email, hashedPassword, referralCode, ip],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to create user' });
                    }

                    const userId = this.lastID;

                    // Initialize earnings
                    db.run('INSERT INTO earnings (user_id, amount) VALUES (?, 0)', [userId], (err) => {
                        if (err) {
                            console.error('Error creating earnings record:', err);
                        }
                    });

                    // Generate JWT token
                    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '7d' });

                    res.json({
                        message: 'User registered successfully',
                        token,
                        user: { id: userId, username, email, referralCode }
                    });
                }
            );
        });
    });
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                referralCode: user.referral_code
            }
        });
    });
});

// Get user dashboard data
app.get('/api/dashboard', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.get(`SELECT u.*, COALESCE(e.amount, 0) as earnings, 
            (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as total_clicks
            FROM users u
            LEFT JOIN earnings e ON u.id = e.user_id
            WHERE u.id = ?`, [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get recent referrals
        db.all(`SELECT * FROM referrals WHERE referrer_id = ? ORDER BY clicked_at DESC LIMIT 10`, 
            [userId], (err, referrals) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.json({
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    referralCode: user.referral_code,
                    earnings: parseFloat(user.earnings || 0),
                    totalClicks: user.total_clicks || 0
                },
                referrals: referrals || []
            });
        });
    });
});

// Handle referral link click
app.get('/api/refer/:code', (req, res) => {
    const referralCode = req.params.code.toUpperCase();
    const visitorIP = getClientIP(req);

    // Find user by referral code
    db.get('SELECT * FROM users WHERE referral_code = ?', [referralCode], (err, referrer) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!referrer) {
            return res.redirect('/?error=invalid_referral');
        }

        // Check if this IP has already clicked this referral link today
        const today = new Date().toISOString().split('T')[0];
        db.get(`SELECT * FROM referrals 
                WHERE referrer_id = ? AND visitor_ip = ? 
                AND DATE(clicked_at) = DATE('now')`, 
            [referrer.id, visitorIP], (err, existingClick) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Allow the click but only reward once per IP per day
            if (!existingClick) {
                // Add referral click
                db.run('INSERT INTO referrals (referrer_id, visitor_ip, earned) VALUES (?, ?, 1)',
                    [referrer.id, visitorIP], (err) => {
                    if (err) {
                        console.error('Error recording referral:', err);
                    } else {
                        // Update earnings
                        db.run(`UPDATE earnings SET amount = amount + 1, last_updated = CURRENT_TIMESTAMP 
                                WHERE user_id = ?`, [referrer.id], (err) => {
                            if (err) {
                                console.error('Error updating earnings:', err);
                            }
                        });
                    }
                });
            }

            // Redirect to registration page with referral code
            res.redirect(`/?ref=${referralCode}`);
        });
    });
});

// Get real-time earnings update
app.get('/api/earnings', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.get(`SELECT COALESCE(e.amount, 0) as earnings,
            (SELECT COUNT(*) FROM referrals WHERE referrer_id = ?) as total_clicks
            FROM earnings e
            WHERE e.user_id = ?`, [userId, userId], (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        res.json({
            earnings: parseFloat(data?.earnings || 0),
            totalClicks: data?.total_clicks || 0
        });
    });
});

app.listen(PORT, () => {
    console.log(`PisoKadaInvite server running on http://localhost:${PORT}`);
});

