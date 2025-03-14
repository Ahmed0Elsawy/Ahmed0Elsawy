const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const flash = require('connect-flash');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = 3000;

// MongoDB connection string
const mongoURI = 'mongodb://localhost:27017';
const dbName = 'mental_health';
let db;

// Connect to MongoDB
async function connectToMongo() {
  try {
    const client = new MongoClient(mongoURI);
    await client.connect();
    console.log('Connected to MongoDB');
    db = client.db(dbName);
    return db;
  } catch (err) {
    console.error('Error connecting to MongoDB:', err);
    process.exit(1);
  }
}

// Configure middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Session and flash setup
app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());

// Make flash messages available to all templates
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success');
  res.locals.error_msg = req.flash('error');
  res.locals.messages = [];
  
  // Format flash messages for the template
  const successMessages = req.flash('success');
  const errorMessages = req.flash('error');
  
  successMessages.forEach(message => {
    res.locals.messages.push({ category: 'success', text: message });
  });
  
  errorMessages.forEach(message => {
    res.locals.messages.push({ category: 'error', text: message });
  });
  
  next();
});

// Load encryption key
function loadKey() {
  try {
    return fs.readFileSync('secret.key');
  } catch (error) {
    console.error('Error loading encryption key:', error);
    // Use the default key if the file doesn't exist
    return Buffer.from('HWXRFHbS1X_KQUuOJUQ0M_clAvDZotOgN8ce2I1Zh2E=', 'base64');
  }
}

const key = loadKey();

// Decryption function compatible with the format used in the application
function decrypt(text) {
  if (!text) return null;
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = textParts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', key.slice(0, 32), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return 'Decryption failed';
  }
}

// Route to show all users with decrypted data
app.get('/', async (req, res) => {
  try {
    const users = await db.collection('users').find().toArray();
    
    const decryptedUsers = users.map(user => {
      try {
        return {
          _id: user._id,
          username: user.username,
          name: user.name ? decrypt(user.name) : null,
          cgpa: user.cgpa ? decrypt(user.cgpa) : null,
          college: user.college ? decrypt(user.college) : null,
          email: user.email ? decrypt(user.email) : null,
          gender: user.gender ? decrypt(user.gender) : null,
          phone: user.phone ? decrypt(user.phone) : null,
          password: user.password ? decrypt(user.password) : null,
          emotional_state: user.emotional_state ? decrypt(user.emotional_state) : null,
          main_concerns: user.main_concerns ? decrypt(user.main_concerns) : null,
          coping_strategies: user.coping_strategies ? decrypt(user.coping_strategies) : null,
          support_type: user.support_type ? decrypt(user.support_type) : null,
          distress_level: user.distress_level, // Not encrypted
          academic_challenges: user.academic_challenges ? decrypt(user.academic_challenges) : null,
          physical_wellbeing: user.physical_wellbeing ? decrypt(user.physical_wellbeing) : null,
          support_network: user.support_network ? decrypt(user.support_network) : null,
          daily_routine: user.daily_routine ? decrypt(user.daily_routine) : null,
          setback_handling: user.setback_handling ? decrypt(user.setback_handling) : null,
          help_seeking: user.help_seeking ? decrypt(user.help_seeking) : null,
          health_challenges: user.health_challenges ? decrypt(user.health_challenges) : null,
          substance_use: user.substance_use ? decrypt(user.substance_use) : null
        };
      } catch (e) {
        req.flash('error', `Decryption failed for user ID ${user._id}: ${e.message}`);
        return {
          _id: user._id,
          username: user.username,
          decryption_error: true
        };
      }
    });
    
    res.render('decrypted_data', { users: decryptedUsers });
  } catch (err) {
    req.flash('error', 'Database error: ' + err.message);
    res.render('decrypted_data', { users: [] });
  }
});

// Start server
async function startServer() {
  await connectToMongo();
  
  app.listen(PORT, () => {
    console.log(`Decryption server running on port ${PORT}`);
  });
}

startServer();
