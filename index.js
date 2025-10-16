const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const morgan = require('morgan');
const winston = require('winston');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || "replace-with-secure-secret";
const apiTokens = [];
const TOKEN_SCOPES = ['read', 'add', 'delete'];

const app = express();
const db = new sqlite3.Database('./user_data.db');

app.use(helmet());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'app.log' })
  ]
});

app.use(session({
    secret: 'very-secure-random-secret', // replace with env var in prod
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport user serialization
passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((user, done) => {
    done(null, user);
});

// Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: 'GOOGLE_CLIENT_ID', // TODO: replace
    clientSecret: 'GOOGLE_CLIENT_SECRET', // TODO: replace
    callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));
// GitHub OAuth strategy
passport.use(new GitHubStrategy({
    clientID: 'GITHUB_CLIENT_ID', // TODO: replace
    clientSecret: 'GITHUB_CLIENT_SECRET', // TODO: replace
    callbackURL: '/auth/github/callback'
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));
// Facebook OAuth strategy
passport.use(new FacebookStrategy({
    clientID: 'FACEBOOK_APP_ID', // TODO: replace
    clientSecret: 'FACEBOOK_APP_SECRET', // TODO: replace
    callbackURL: '/auth/facebook/callback',
    profileFields: ['id', 'displayName', 'emails']
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
});

// Profile view (authenticated)
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.render('profile', { error: 'User not found', user: req.user });
    res.render('profile', { user });
  });
});
// Logout route
app.get('/logout', (req, res) => {
    req.logout(() => {
      res.redirect('/');
    });
});

app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// Create table
const createTable = `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    surname TEXT NOT NULL,
    age INTEGER NOT NULL
);`;
logger.info('Server start sequence');
db.run(createTable, err => {
  if (err) logger.error('Failed to create users table: ' + err);
  else logger.info('Users table ensured');
});

// Update users table: add bio, profile_picture, social_links if not exists
const addProfileColumns = `
ALTER TABLE users ADD COLUMN bio TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN profile_picture TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN social_links TEXT DEFAULT '';
`;
db.serialize(() => {
  db.run("PRAGMA foreign_keys=ON");
  // Add columns if missing
  db.get("SELECT bio, profile_picture, social_links FROM users LIMIT 1", [], function(err) {
    if (err) {
      db.exec(addProfileColumns, () => {});
      logger.info('Added profile columns to users table');
    }
  });
});

// Add role column if not exists
const addRoleColumn = `ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';`;
db.get("SELECT role FROM users LIMIT 1", [], function(err) {
    if (err) db.exec(addRoleColumn, () => logger.info('Added role column'));
});
// Middleware to check if user is authenticated and admin
function isAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    return res.status(403).send('Admins only');
}
// Middleware for self or admin
function isSelfOrAdmin(req, res, next) {
    const { id } = req.params;
    if (req.isAuthenticated() && (req.user.role === 'admin' || req.user.id == id)) return next();
    return res.status(403).send('Forbidden');
}

const upload = multer({
  dest: './uploads/profile_pics',
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
      if(/\.(jpg|jpeg|png|gif)$/i.test(file.originalname)) cb(null, true);
      else cb(new Error('Only image files allowed!'));
  }
});
app.use('/uploads/profile_pics', express.static(path.join(__dirname, 'uploads/profile_pics')));

// Profile edit HTML form
app.get('/profile/edit', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/');
    const userId = req.user.id || req.user.username || req.user.provider_id;
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) return res.status(500).send('User not found');
        res.send(`
          <h1>Edit Profile</h1>
          <form action="/profile/edit" method="POST" enctype="multipart/form-data">
            <label>Bio:</label><br>
            <textarea name="bio">${user.bio || ''}</textarea><br><br>
            <label>Profile Picture:</label><br>
            ${user.profile_picture ? `<img src="/uploads/profile_pics/${user.profile_picture}" height="80"><br>`: ''}
            <input type="file" name="profile_picture"><br><br>
            <label>Social (JSON: {"twitter":"","linkedin":"",...}):</label><br>
            <input name="social_links" type="text" value='${user.social_links || ''}'><br><br>
            <button type="submit">Save</button>
          </form>
        `);
    });
});
// Profile save logic
app.post('/profile/edit', upload.single('profile_picture'), (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/');
    const userId = req.user.id || req.user.username || req.user.provider_id;
    const bio = req.body.bio || '';
    let picFilename = '';
    if(req.file) picFilename = req.file.filename;
    let social = req.body.social_links || '';
    db.run("UPDATE users SET bio = ?, profile_picture = COALESCE(NULLIF(?, ''), profile_picture), social_links = ? WHERE id = ?",
      [bio, picFilename, social, userId],
      err => {
        if(err) {
          logger.error(`Profile update DB error: ${err}`);
          return res.status(500).send('Database error');
        }
        logger.info(`User ${userId} updated profile info.`);
        res.redirect('/profile');
      }
    );
});

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

function getUserFromReq(req) {
  return req.isAuthenticated() ? req.user : null;
}
app.use((req, res, next) => {
  res.locals.user = getUserFromReq(req);
  res.locals.isAdmin = res.locals.user && res.locals.user.role === 'admin';
  next();
});
app.get('/', (req, res) => {
  res.render('home', {});
});
app.get('/admin', (req, res) => {
  res.render('admin', { user: res.locals.user });
});

// Handle form POST
app.post('/submit', (req, res) => {
    const { name, surname, age } = req.body;
    const safeName = String(name).replace(/[^a-zA-Z\s'-]/g, '').trim();
    const safeSurname = String(surname).replace(/[^a-zA-Z\s'-]/g, '').trim();
    const safeAge = Number(age);
    logger.info(`Received form submit: { name: ${safeName}, surname: ${safeSurname}, age: ${safeAge} }`);
    if (!safeName || !safeSurname || isNaN(safeAge) || safeAge < 1 || safeAge > 120) {
        logger.warn('Invalid form input - rejected');
        return res.status(400).send('Invalid input.');
    }
    db.run('INSERT INTO users (name, surname, age) VALUES (?, ?, ?)', [safeName, safeSurname, safeAge], (err) => {
        if (err) {
            logger.error('Database error (insert): ' + err);
            return res.status(500).send('Database error.');
        }
        logger.info(`User added: ${safeName} ${safeSurname} (${safeAge})`);
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
app.delete('/api/users/:id', isAdmin, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
        logger.warn(`Invalid delete attempt for user id: ${req.params.id}`);
        return res.status(400).json({ error: 'Invalid user id.' });
    }
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
        if (err) {
            logger.error('Database error (delete): ' + err);
            return res.status(500).json({error: 'Database error.'});
        }
        if (this.changes === 0) {
            logger.warn(`Delete failed, user not found: id ${id}`);
            return res.status(404).json({error: 'User not found.'});
        }
        logger.info(`User deleted: id ${id}`);
        res.json({ success: true });
    });
});

app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err}`);
  res.status(500).send('Internal server error.');
});

// User registration page
app.get('/signup', (req, res) => {
  res.render('signup');
});
app.post('/signup', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).send('Missing fields');
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, existing) => {
    if (existing) return res.status(409).send('Username taken');
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', [username, hash, email, 'user'], (err) => {
      if (err) return res.status(500).send('DB error');
      logger.info(`User registered: ${username}`);
      res.redirect('/login');
    });
  });
});
// Login page
app.get('/login', (req, res) => {
  res.render('login');
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.status(401).send('Invalid username or password');
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).send('Invalid username or password');
    req.login(user, err => {
      if (err) return res.status(500).send('Session/auth error');
      logger.info(`User login: ${username}`);
      return res.redirect('/profile');
    });
  });
});
// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});
// Password reset page
app.get('/reset-password', (req, res) => {
  res.render('reset_password');
});
// Password reset logic
app.post('/reset-password', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).send('Missing fields');
  db.get('SELECT * FROM users WHERE username = ? AND email = ?', [username, email], (err, user) => {
    if (!user) return res.status(401).send('User not found');
    const hash = bcrypt.hashSync(password, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hash, user.id], err => {
      if (err) return res.status(500).send('DB error');
      logger.info(`User password reset: ${username}`);
      res.redirect('/login');
    });
  });
});
// Only allow authenticated users to access/edit /profile
app.get('/profile', (req, res, next) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
});
app.get('/profile/edit', (req, res, next) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
});

// View token management
app.get('/profile/tokens', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    const userTokens = apiTokens.filter(t => t.userId === req.user.id);
    res.render('tokens', { userTokens });
});
app.post('/profile/tokens', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    let scopes = req.body.scopes;
    if (!Array.isArray(scopes)) scopes = [scopes];
    // validate scopes
    scopes = scopes.filter(s => TOKEN_SCOPES.includes(s));
    const payload = {
        userId: req.user.id,
        scopes
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    apiTokens.push({ token, userId: req.user.id, scopes });
    logger.info(`API token created for user ${req.user.id} with scopes ${scopes.join(',')}`);
    res.redirect('/profile/tokens');
});
// token-auth middleware for API
function requireApiScope(required) {
    return (req, res, next) => {
        let auth = req.headers['authorization'] || '';
        if (!auth.startsWith('Bearer ')) return res.status(401).send('Missing bearer token');
        const t = auth.split(' ')[1];
        try {
            const decoded = jwt.verify(t, JWT_SECRET);
            req.apiUser = decoded;
            if (!decoded.scopes.includes(required)) return res.status(403).send('Insufficient scope');
            next();
        } catch(e) {
            return res.status(401).send('Invalid or expired token');
        }
    };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
    console.log(`Server running on http://localhost:${PORT}`);
});
