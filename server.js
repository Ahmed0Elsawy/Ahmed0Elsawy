const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const flash = require('connect-flash');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 4000;

const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const dbName = 'mental_health';
let db;

async function connectToMongo() {
  try {
    // Removed deprecated options
    const client = new MongoClient(mongoURI, {
      serverSelectionTimeoutMS: 5000 // 5 second timeout
    });
    await client.connect();
    console.log('Connected to MongoDB');
    db = client.db(dbName);
    
    await db.command({ ping: 1 });
    console.log("Database ping successful");
    
    return db;
  } catch (err) {
    console.error('Error connecting to MongoDB:', err);
    process.exit(1);
  }
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Adjust path as needed
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));
app.use(flash());

function loadKey() {
  try {
    const keyPath = process.env.KEY_PATH || 'secret.key';
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath);
    } else {
      console.log('Encryption key not found, generating new key');
      const newKey = crypto.randomBytes(32);
      try {
        fs.writeFileSync(keyPath, newKey);
        return newKey;
      } catch (writeError) {
        console.error('Failed to write new encryption key:', writeError);
        throw new Error('Cannot create encryption key file');
      }
    }
  } catch (error) {
    console.error('Critical error with encryption key:', error);
    process.exit(1); 
  }
}

const key = loadKey();

function encrypt(text) {
  if (!text) return null;
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key.slice(0, 32), iv);
    let encrypted = cipher.update(text.toString(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
}

function decrypt(text) {
  if (!text) return null;
  try {
    const textParts = text.split(':');
    if (textParts.length !== 2) {
      throw new Error('Invalid encrypted text format');
    }
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = textParts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', key.slice(0, 32), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

function isAuthenticated(req, res, next) {
  if (req.session.user_id) {
    return next();
  }
  req.flash('error', 'Please log in to access this page');
  res.redirect('/login');
}

async function isAdmin(req, res, next) {
  if (!req.session.user_id) {
    req.flash('error', 'Please log in to access this page');
    return res.redirect('/login');
  }
  
  try {
    const user = await db.collection('users').findOne({ _id: req.session.user_id });
    if (user && user.role === 'admin') {
      return next();
    }
    req.flash('error', 'You do not have permission to access this page');
    res.redirect('/home');
  } catch (err) {
    console.error('Error checking admin status:', err);
    req.flash('error', 'An error occurred. Please try again.');
    res.redirect('/home');
  }
}

app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success');
  res.locals.error_msg = req.flash('error');
  res.locals.messages = [];

  const successMessages = req.flash('success');
  const errorMessages = req.flash('error');
  const warningMessages = req.flash('warning');
  
  successMessages.forEach(message => {
    res.locals.messages.push({ category: 'success', text: message });
  });
  
  errorMessages.forEach(message => {
    res.locals.messages.push({ category: 'error', text: message });
  });
  
  warningMessages.forEach(message => {
    res.locals.messages.push({ category: 'warning', text: message });
  });

  res.locals.isAuthenticated = !!req.session.user_id;
  
  next();
});

app.get('/', (req, res) => {
  res.redirect('/home');
});

app.get('/home', (req, res) => {
  res.render('home');
});

app.get('/Home', (req, res) => {
  res.redirect('/home');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { id, name, cgpa, college, email, gender, phone, username, password } = req.body;

  if (!username || !password || !email || !name) {
    req.flash('error', 'Please fill in all required fields.');
    return res.redirect('/signup');
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    req.flash('error', 'Please enter a valid email address.');
    return res.redirect('/signup');
  }
  
  if (password.length < 8) {
    req.flash('error', 'Password must be at least 8 characters long.');
    return res.redirect('/signup');
  }

  try {
    const encrypted_name = encrypt(name);
    const encrypted_cgpa = encrypt(cgpa);
    const encrypted_college = encrypt(college);
    const encrypted_email = encrypt(email);
    const encrypted_gender = encrypt(gender);
    const encrypted_phone = encrypt(phone);
    const encrypted_password = encrypt(password);

    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      req.flash('error', 'Username already exists. Try a different one.');
      return res.redirect('/signup');
    }

    const existingEmail = await db.collection('users').find().toArray();
    const emailExists = existingEmail.some(user => {
      try {
        return decrypt(user.email) === email;
      } catch (err) {
        console.error('Decryption error while checking emails:', err);
        return false;
      }
    });

    if (emailExists) {
      req.flash('error', 'Email already registered. Please use a different email or try logging in.');
      return res.redirect('/signup');
    }

    // Insert new user
    await db.collection('users').insertOne({
      _id: id || new ObjectId().toString(), 
      name: encrypted_name,
      cgpa: encrypted_cgpa,
      college: encrypted_college,
      email: encrypted_email,
      gender: encrypted_gender,
      phone: encrypted_phone,
      username,
      password: encrypted_password,
      role: 'user', 
      created_at: new Date(),
      emotional_state: null,
      main_concerns: null,
      coping_strategies: null,
      support_type: null,
      distress_level: null,
      academic_challenges: null,
      physical_wellbeing: null,
      support_network: null,
      daily_routine: null,
      setback_handling: null,
      help_seeking: null,
      health_challenges: null,
      substance_use: null
    });
    
    req.flash('success', 'Account created successfully. Please log in.');
    res.redirect('/login');
  } catch (err) {
    console.error('Error in signup process:', err);
    if (err.message === 'Failed to encrypt data') {
      req.flash('error', 'System error: Unable to securely save your information');
    } else {
      req.flash('error', 'Error creating account. Please try again later.');
    }
    res.redirect('/signup');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    req.flash('error', 'Please enter both username and password');
    return res.redirect('/login');
  }
  
  try {
    const user = await db.collection('users').findOne({ username });
    
    if (!user) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }
    
    try {
      const decrypted_password = decrypt(user.password);
      if (decrypted_password === password) {
        req.session.user_id = user._id;

        console.log(`User ${username} logged in successfully at ${new Date()}`);
        req.flash('success', 'Login successful!');
        
        // Check if user has completed questionnaire
        if (!user.emotional_state) {
          return res.redirect('/questionnaire');
        }
        return res.redirect('/home');
      } else {
        console.log(`Failed login attempt for user ${username} at ${new Date()}`);
        req.flash('error', 'Invalid username or password');
        return res.redirect('/login');
      }
    } catch (decryptError) {
      console.error('Password decryption error:', decryptError);
      req.flash('error', 'Authentication error. Please try again later.');
      return res.redirect('/login');
    }
  } catch (err) {
    console.error('Login database error:', err);
    req.flash('error', 'An error occurred. Please try again later.');
    res.redirect('/login');
  }
});

app.get('/questionnaire', isAuthenticated, (req, res) => {
  res.render('questionnaire', { user_id: req.session.user_id });
});

app.post('/questionnaire', isAuthenticated, async (req, res) => {
  const user_id = req.session.user_id;

  const {
    emotional_state,
    main_concerns,
    coping_strategies,
    support_type,
    distress_level,
    academic_challenges,
    physical_wellbeing,
    support_network,
    daily_routine,
    setback_handling,
    help_seeking,
    health_challenges,
    substance_use
  } = req.body;

  if (!emotional_state || !main_concerns || !distress_level) {
    req.flash('error', 'Please answer all required questions');
    return res.redirect('/questionnaire');
  }

  const distressLevel = parseInt(distress_level);
  if (isNaN(distressLevel) || distressLevel < 1 || distressLevel > 5) {
    req.flash('error', 'Invalid distress level. Please select a value between 1 and 5.');
    return res.redirect('/questionnaire');
  }

  try {
    const encrypted_emotional_state = encrypt(emotional_state);
    const encrypted_main_concerns = encrypt(main_concerns);
    const encrypted_coping_strategies = encrypt(coping_strategies);
    const encrypted_support_type = encrypt(support_type);
    const encrypted_academic_challenges = encrypt(academic_challenges);
    const encrypted_physical_wellbeing = encrypt(physical_wellbeing);
    const encrypted_support_network = encrypt(support_network);
    const encrypted_daily_routine = encrypt(daily_routine);
    const encrypted_setback_handling = encrypt(setback_handling);
    const encrypted_help_seeking = encrypt(help_seeking);
    const encrypted_health_challenges = encrypt(health_challenges);
    const encrypted_substance_use = encrypt(substance_use);

    const userExists = await db.collection('users').findOne({ _id: user_id });
    if (!userExists) {
      req.flash('error', 'User not found. Please login again.');
      return res.redirect('/login');
    }

    const updateResult = await db.collection('users').updateOne(
      { _id: user_id },
      { $set: {
          emotional_state: encrypted_emotional_state,
          main_concerns: encrypted_main_concerns,
          coping_strategies: encrypted_coping_strategies,
          support_type: encrypted_support_type,
          distress_level: distressLevel, 
          academic_challenges: encrypted_academic_challenges,
          physical_wellbeing: encrypted_physical_wellbeing,
          support_network: encrypted_support_network,
          daily_routine: encrypted_daily_routine,
          setback_handling: encrypted_setback_handling,
          help_seeking: encrypted_help_seeking,
          health_challenges: encrypted_health_challenges,
          substance_use: encrypted_substance_use,
          last_updated: new Date()
        }
      }
    );

    if (updateResult.matchedCount === 0) {
      throw new Error('User not found in database');
    }
    
    if (distressLevel >= 4) {
      req.flash('warning', 'Based on your responses, we encourage you to consider speaking with a mental health professional.');
    }
    
    req.flash('success', 'Responses recorded successfully.');
    res.redirect('/home');
  } catch (err) {
    console.error('Error saving questionnaire responses:', err);
    req.flash('error', 'Error saving responses. Please try again later.');
    res.redirect('/questionnaire');
  }
});

app.get('/concern_counts', isAdmin, async (req, res) => {
  try {
    const count = await db.collection('users').countDocuments();
    
    const healthChallenges = [
      "Addiction or Substance Use Concerns",
      "Physical Disability",
      "Mental Health Condition",
      "Learning Disability",
      "None",
      "Prefer Not to Share"
    ];
    
    const counts = {};
    
    const allUsers = await db.collection('users').find().toArray();
    
    healthChallenges.forEach(challenge => {
      counts[challenge] = 0;
    });
    
    allUsers.forEach(user => {
      if (!user.health_challenges) return;
      
      try {
        const challenge = decrypt(user.health_challenges);
        if (healthChallenges.includes(challenge)) {
          counts[challenge]++;
        } else if (challenge) {
          counts["Other"] = (counts["Other"] || 0) + 1;
        }
      } catch (err) {
        console.error('Decryption error for user:', user._id, err);
        counts["Error/Unknown"] = (counts["Error/Unknown"] || 0) + 1;
      }
    });
    
    res.render('concern_counts', { counts, count });
  } catch (err) {
    console.error('Error retrieving concern counts:', err);
    res.status(500).render('error', { 
      error: 'Error retrieving data. Please try again later.' 
    });
  }
});

app.get('/analytics', isAdmin, async (req, res) => {
  try {
    const totalUsers = await db.collection('users').countDocuments();
    const allUsers = await db.collection('users').find().toArray();
    
    const analytics = {
      totalUsers,
      emotionalState: {},
      mainConcerns: {},
      distressLevels: {
        '1': 0, '2': 0, '3': 0, '4': 0, '5': 0, 'unknown': 0
      },
      decryptionErrors: 0
    };
    
    allUsers.forEach(user => {
      if (user.distress_level && Object.keys(analytics.distressLevels).includes(user.distress_level.toString())) {
        analytics.distressLevels[user.distress_level.toString()]++;
      } else {
        analytics.distressLevels['unknown']++;
      }
      
      try {
        if (user.emotional_state) {
          const state = decrypt(user.emotional_state);
          if (state) {
            analytics.emotionalState[state] = (analytics.emotionalState[state] || 0) + 1;
          }
        }
        
        if (user.main_concerns) {
          const concern = decrypt(user.main_concerns);
          if (concern) {
            analytics.mainConcerns[concern] = (analytics.mainConcerns[concern] || 0) + 1;
          }
        }
      } catch (err) {
        console.error('Error decrypting data for user:', user._id, err);
        analytics.decryptionErrors++;
      }
    });
    
    res.render('analytics', { analytics });
  } catch (err) {
    console.error('Error generating analytics:', err);
    res.status(500).render('error', { 
      error: 'Unable to generate analytics at this time. Please try again later.' 
    });
  }
});

app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: req.session.user_id });
    
    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('/home');
    }
    
    try {
      const userData = {
        username: user.username,
        name: decrypt(user.name),
        email: decrypt(user.email),
        college: decrypt(user.college) || 'Not provided',
        phone: decrypt(user.phone) || 'Not provided',
        cgpa: decrypt(user.cgpa) || 'Not provided',
        gender: decrypt(user.gender) || 'Not provided',
        joined: user.created_at || 'Unknown'
      };
      
      res.render('profile', { user: userData });
    } catch (decryptErr) {
      console.error('Error decrypting user data:', decryptErr);
      req.flash('error', 'Error retrieving your profile information');
      res.redirect('/questionnaire');
    }
  } catch (err) {
    console.error('Database error in profile route:', err);
    req.flash('error', 'Error loading profile. Please try again later.');
    res.redirect('/questionnaire');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Logout failed');
    }
    res.redirect('/login');
  });
});

app.get('/api/health', (req, res) => {
  try {
    if (db) {
      res.status(200).json({ status: 'healthy', database: 'connected' });
    } else {
      res.status(500).json({ status: 'unhealthy', database: 'disconnected' });
    }
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.use((err, req, res, next) => {
  console.error('Unhandled application error:', err);

  let errorMessage = 'An unexpected error occurred';
  
  if (process.env.NODE_ENV === 'development') {
    errorMessage = err.stack || err.message || 'Unknown error';
  } else {
    if (err.type === 'entity.parse.failed') {
      errorMessage = 'Invalid request format';
    } else if (err.name === 'ValidationError') {
      errorMessage = 'Invalid data provided';
    } else if (err.name === 'UnauthorizedError') {
      errorMessage = 'Authentication required';
    }
  }
  
  if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') > -1)) {
    return res.status(500).json({ error: errorMessage });
  } else {
    res.status(500).render('error', { error: errorMessage });
  }
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('Shutting down server...');
  if (db && db.client) {
    console.log('Closing database connection...');
    db.client.close();
  }
  process.exit(0);
}

async function startServer() {
  try {
    await connectToMongo();
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };