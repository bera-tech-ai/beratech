import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'devs-arena-super-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/devs-arena')
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.log('❌ MongoDB Connection Error:', err));

// Database Models
const userSchema = new mongoose.Schema({
  githubId: String,
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: String,
  name: String,
  avatar: { type: String, default: '' },
  skillLevel: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'], default: 'Beginner' },
  focusArea: { type: String, enum: ['Frontend', 'Backend', 'Full-Stack', 'Mobile', 'Data Science', 'DevOps'], default: 'Full-Stack' },
  isStudent: { type: Boolean, default: false },
  country: String,
  isOnline: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Passport Configuration
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      console.log('🔐 Login attempt:', email);
      
      const user = await User.findOne({ 
        $or: [{ email: email }, { username: email }] 
      });
      
      if (!user) {
        console.log('❌ User not found:', email);
        return done(null, false, { message: 'User not found' });
      }

      if (!user.password) {
        console.log('❌ No password set for user');
        return done(null, false, { message: 'Please use GitHub login' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        console.log('❌ Invalid password for user:', email);
        return done(null, false, { message: 'Invalid password' });
      }

      console.log('✅ Login successful for user:', user.username);
      return done(null, user);
    } catch (error) {
      console.error('💥 Login error:', error);
      return done(error);
    }
  }
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID || 'github-client-id',
  clientSecret: process.env.GITHUB_CLIENT_SECRET || 'github-client-secret',
  callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:5000/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    
    if (!user) {
      user = new User({
        githubId: profile.id,
        username: profile.username,
        email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
        name: profile.displayName || profile.username,
        avatar: profile.photos?.[0]?.value
      });
      await user.save();
    }
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// Authentication Routes - FIXED REGISTRATION FLOW
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', req.body);
    const { username, email, password, name, skillLevel, focusArea, isStudent, country } = req.body;
    
    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, and password are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      name: name || username,
      skillLevel: skillLevel || 'Beginner',
      focusArea: focusArea || 'Full-Stack',
      isStudent: isStudent === 'true',
      country: country || ''
    });
    
    await user.save();
    console.log('✅ User registered successfully:', user.username);
    
    // ✅ FIXED: Don't auto-login, just return success
    res.json({ 
      success: true, 
      message: 'Registration successful! Please login with your credentials.',
      user: { 
        username: user.username,
        email: user.email
      } 
    });
    
  } catch (error) {
    console.error('💥 Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});

app.post('/api/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('💥 Auth error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Authentication error' 
      });
    }
    
    if (!user) {
      console.log('❌ Login failed:', info?.message);
      return res.status(401).json({ 
        success: false, 
        message: info?.message || 'Invalid credentials' 
      });
    }
    
    req.login(user, (err) => {
      if (err) {
        console.error('💥 Session error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Login failed' 
        });
      }
      
      console.log('✅ User logged in successfully:', user.username);
      res.json({ 
        success: true, 
        message: 'Login successful!', 
        user: { 
          id: user._id, 
          username: user.username, 
          name: user.name,
          avatar: user.avatar,
          skillLevel: user.skillLevel 
        } 
      });
    });
  })(req, res, next);
});

app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/callback', 
  passport.authenticate('github', { 
    failureRedirect: '/?auth=github_failed',
    successRedirect: '/?auth=github_success'
  })
);

app.post('/api/auth/logout', (req, res) => {
  console.log('🚪 Logout attempt for user:', req.user?.username);
  req.logout((err) => {
    if (err) {
      console.error('💥 Logout error:', err);
      return res.status(500).json({ 
        success: false, 
        message: 'Logout failed' 
      });
    }
    res.json({ 
      success: true, 
      message: 'Logout successful' 
    });
  });
});

app.get('/api/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      success: true, 
      user: {
        id: req.user._id,
        username: req.user.username,
        name: req.user.name,
        avatar: req.user.avatar,
        skillLevel: req.user.skillLevel,
        focusArea: req.user.focusArea
      }
    });
  } else {
    res.json({ success: false, user: null });
  }
});

// AI Assistant
app.post('/api/ai/chat', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Please login to use AI assistant' });
  }
  
  try {
    const { message } = req.body;
    
    const responses = {
      'hello': 'Hello! 👋 Welcome to DEVS ARENA! How can I help you with your coding today?',
      'help': 'I can help you with:\n• Code explanations\n• Debugging assistance\n• Learning resources\n• Best practices\n• Project ideas\nWhat do you need help with?',
      'html': 'HTML is the standard markup language for creating web pages. It provides the structure of a webpage.',
      'css': 'CSS is used to style and layout web pages. It controls colors, fonts, spacing, and responsive design.',
      'javascript': 'JavaScript makes web pages interactive. It\'s used for both frontend and backend development.',
      'registration': 'After registration, you\'ll be redirected to the login page to sign in with your new credentials.'
    };
    
    const response = responses[message.toLowerCase()] || 
      `I understand you're asking about "${message}". I can help with programming concepts, debugging, and learning resources. Could you provide more details?`;

    res.json({ success: true, response });
  } catch (error) {
    res.status(500).json({ success: false, message: 'AI service unavailable' });
  }
});

// Socket.io
const activeUsers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  socket.on('user_online', async (userId) => {
    activeUsers.set(socket.id, userId);
    await User.findByIdAndUpdate(userId, { isOnline: true });
    
    io.emit('users_online_update', {
      online: Array.from(activeUsers.values()).length
    });
  });

  socket.on('disconnect', async () => {
    const userId = activeUsers.get(socket.id);
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false });
      activeUsers.delete(socket.id);
      
      io.emit('users_online_update', {
        online: Array.from(activeUsers.values()).length
      });
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('\n🚀 DEVS ARENA Server Started Successfully!');
  console.log('📍 Server URL: http://localhost:' + PORT);
  console.log('\n✅ Authentication Flow:');
  console.log('   📝 Registration → Login Page');
  console.log('   🔐 Login with Credentials');
  console.log('   ✅ Access Full Platform');
});
