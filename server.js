import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';
import LocalStrategy from 'passport-local';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { GridFSBucket } from 'mongodb';
import OpenAI from 'openai';
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
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.log('❌ MongoDB Connection Error:', err));

// Database Models
const userSchema = new mongoose.Schema({
  githubId: String,
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: String,
  name: String,
  avatar: { type: String, default: '/default-avatar.png' },
  skillLevel: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'], default: 'Beginner' },
  focusArea: { type: String, enum: ['Frontend', 'Backend', 'Full-Stack', 'Mobile', 'Data Science', 'DevOps'], default: 'Frontend' },
  isStudent: { type: Boolean, default: false },
  country: String,
  bio: String,
  skills: [String],
  joinedAt: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false },
  lastActive: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tags: [String],
  category: String,
  files: [{
    name: String,
    content: String,
    language: String
  }],
  isPublic: { type: Boolean, default: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likesCount: { type: Number, default: 0 },
  views: { type: Number, default: 0 }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  room: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: String,
  type: { type: String, enum: ['text', 'code', 'file'], default: 'text' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);

// Passport Configuration
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ 
        $or: [{ email: email }, { username: email }] 
      });
      
      if (!user) {
        return done(null, false, { message: 'User not found' });
      }

      if (!user.password) {
        return done(null, false, { message: 'Please use GitHub login or reset password' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return done(null, false, { message: 'Invalid password' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    
    if (!user) {
      user = new User({
        githubId: profile.id,
        username: profile.username,
        email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
        name: profile.displayName,
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

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, name, skillLevel, focusArea, isStudent, country } = req.body;
    
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
      name,
      skillLevel,
      focusArea,
      isStudent: isStudent === 'true',
      country
    });
    
    await user.save();
    
    // Auto login after registration
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ 
          success: false, 
          message: 'Auto login failed' 
        });
      }
      res.json({ 
        success: true, 
        message: 'Registration successful', 
        user: { 
          id: user._id, 
          username: user.username, 
          name: user.name,
          avatar: user.avatar 
        } 
      });
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});

app.post('/api/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return res.status(500).json({ 
        success: false, 
        message: 'Authentication error' 
      });
    }
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: info?.message || 'Invalid credentials' 
      });
    }
    
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ 
          success: false, 
          message: 'Login failed' 
        });
      }
      
      res.json({ 
        success: true, 
        message: 'Login successful', 
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

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/?auth=github_failed' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.post('/api/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
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

// Projects API
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find({ isPublic: true })
      .populate('owner', 'username name avatar')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json({ success: true, projects });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch projects' });
  }
});

app.post('/api/projects', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const project = new Project({
      ...req.body,
      owner: req.user._id
    });
    
    await project.save();
    await project.populate('owner', 'username name avatar');
    
    res.json({ success: true, project });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create project' });
  }
});

// AI Assistant
app.post('/api/ai/chat', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const { message } = req.body;
    
    // Simple AI response (replace with OpenAI API in production)
    const aiResponses = {
      'hello': 'Hello! How can I help you with your coding today?',
      'help': 'I can help you with code explanations, debugging, and learning programming concepts.',
      'html': 'HTML is the standard markup language for creating web pages.',
      'css': 'CSS is used to style and layout web pages.',
      'javascript': 'JavaScript is a programming language that makes web pages interactive.',
      'python': 'Python is a versatile programming language great for web development, data science, and AI.',
      'react': 'React is a JavaScript library for building user interfaces, particularly web applications.',
      'node': 'Node.js is a JavaScript runtime built on Chrome\'s V8 JavaScript engine.',
      'mongodb': 'MongoDB is a NoSQL database that uses JSON-like documents with optional schemas.'
    };
    
    const response = aiResponses[message.toLowerCase()] 
      || `I understand you're asking about "${message}". As an AI assistant, I can help explain programming concepts, help debug code, or suggest learning resources. Could you be more specific about what you need help with?`;
    
    res.json({ success: true, response });
  } catch (error) {
    res.status(500).json({ success: false, message: 'AI service unavailable' });
  }
});

// Socket.io for real-time features
const onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user_online', (userId) => {
    onlineUsers.set(socket.id, userId);
    io.emit('online_users', Array.from(onlineUsers.values()));
  });

  socket.on('join_chat', (room) => {
    socket.join(room);
  });

  socket.on('chat_message', async (data) => {
    try {
      const message = new Message({
        room: data.room,
        user: data.userId,
        content: data.content,
        type: data.type
      });
      
      await message.save();
      await message.populate('user', 'username name avatar');
      
      io.to(data.room).emit('new_message', message);
    } catch (error) {
      socket.emit('error', 'Failed to send message');
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.id);
    io.emit('online_users', Array.from(onlineUsers.values()));
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 DEVS ARENA running on port ${PORT}`);
  console.log(`📧 Authentication System: ACTIVE`);
  console.log(`🗄️ Database: CONNECTED`);
  console.log(`🔌 Socket.IO: READY`);
});
