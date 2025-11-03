import express from 'express';
import mongoose from 'mongoose';
import { createServer } from 'http';
import { Server } from 'socket.io';
import bcrypt from 'bcryptjs';
import session from 'express-session';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GitHubStrategy } from 'passport-github2';
import nodemailer from 'nodemailer';
import Joi from 'joi';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { config } from 'dotenv';

config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server);

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String },
  githubId: { type: String },
  skillLevel: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'] },
  focusAreas: [{ type: String }],
  role: { type: String, enum: ['student', 'professional'], default: 'student' },
  country: { type: String },
  progress: { type: Object, default: {} },
  badges: [{ type: String }],
  githubProfile: { type: String },
  isAdmin: { type: Boolean, default: false },
  aiQueriesToday: { type: Number, default: 0 },
  lastQueryDate: { type: Date },
  newsletterSubscribed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  tags: [{ type: String }],
  category: { type: String },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  files: [{
    name: String,
    path: String,
    size: Number,
    mimetype: String
  }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  views: { type: Number, default: 0 },
  forks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  room: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  attachments: [{
    name: String,
    path: String
  }],
  timestamp: { type: Date, default: Date.now }
});

const APISchema = new mongoose.Schema({
  name: { type: String, required: true },
  endpoint: { type: String, required: true },
  category: { type: String, required: true },
  description: { type: String },
  authRequired: { type: Boolean, default: false },
  examples: { type: Object },
  usageCount: { type: Number, default: 0 },
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const JobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  company: { type: String },
  skills: [{ type: String }],
  posterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  applications: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    appliedAt: { type: Date, default: Date.now }
  }],
  type: { type: String, enum: ['full-time', 'part-time', 'contract', 'internship'] },
  location: { type: String },
  remote: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const Message = mongoose.model('Message', MessageSchema);
const API = mongoose.model('API', APISchema);
const Job = mongoose.model('Job', JobSchema);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_DIR || './uploads');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Passport configuration
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: 'User not found' });
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return done(null, false, { message: 'Invalid password' });
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

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
        name: profile.displayName,
        email: profile.emails?.[0]?.value,
        githubProfile: profile.profileUrl
      });
      await user.save();
    }
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Auth middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
};

const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.status(403).json({ error: 'Admin access required' });
};

// Sample Free APIs
const sampleAPIs = [
  {
    name: "JSONPlaceholder",
    endpoint: "https://jsonplaceholder.typicode.com/posts",
    category: "Development",
    description: "Fake Online REST API for Testing and Prototyping",
    authRequired: false,
    examples: { method: "GET", response: "{ userId: 1, id: 1, title: '...', body: '...' }" }
  },
  {
    name: "OpenWeatherMap",
    endpoint: "https://api.openweathermap.org/data/2.5/weather",
    category: "Weather",
    description: "Current weather data for any location",
    authRequired: true,
    examples: { method: "GET", params: "q=London&appid=API_KEY" }
  },
  {
    name: "CoinGecko",
    endpoint: "https://api.coingecko.com/api/v3/simple/price",
    category: "Crypto",
    description: "Cryptocurrency prices and market data",
    authRequired: false,
    examples: { method: "GET", params: "ids=bitcoin&vs_currencies=usd" }
  }
];

// Initialize APIs
async function initializeAPIs() {
  const count = await API.countDocuments();
  if (count === 0) {
    await API.insertMany(sampleAPIs);
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const schema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      skillLevel: Joi.string().valid('Beginner', 'Intermediate', 'Expert').required(),
      focusAreas: Joi.array().items(Joi.string()),
      role: Joi.string().valid('student', 'professional'),
      country: Joi.string()
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const existingUser = await User.findOne({ email: value.email });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(value.password, 12);
    const user = new User({
      ...value,
      password: hashedPassword
    });

    await user.save();
    req.login(user, (err) => {
      if (err) return res.status(500).json({ error: 'Login failed' });
      res.json({ message: 'Registration successful', user: { id: user._id, name: user.name, email: user.email } });
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', passport.authenticate('local'), (req, res) => {
  res.json({ message: 'Login successful', user: { id: req.user._id, name: req.user.name, email: req.user.email } });
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.post('/api/logout', (req, res) => {
  req.logout(() => {
    res.json({ message: 'Logout successful' });
  });
});

// User Routes
app.get('/api/user', isAuthenticated, (req, res) => {
  res.json({ user: req.user });
});

app.put('/api/user/profile', isAuthenticated, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    res.json({ message: 'Profile updated', user });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Project Routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find()
      .populate('userId', 'name email')
      .sort({ createdAt: -1 });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.post('/api/projects', isAuthenticated, upload.array('files'), async (req, res) => {
  try {
    const { title, description, tags, category } = req.body;
    const files = req.files ? req.files.map(file => ({
      name: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype
    })) : [];

    const project = new Project({
      title,
      description,
      tags: tags ? tags.split(',') : [],
      category,
      userId: req.user._id,
      files
    });

    await project.save();
    res.json({ message: 'Project created', project });
  } catch (error) {
    res.status(500).json({ error: 'Project creation failed' });
  }
});

app.post('/api/projects/:id/like', isAuthenticated, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const likeIndex = project.likes.indexOf(req.user._id);
    if (likeIndex > -1) {
      project.likes.splice(likeIndex, 1);
    } else {
      project.likes.push(req.user._id);
    }

    await project.save();
    res.json({ likes: project.likes.length, liked: likeIndex === -1 });
  } catch (error) {
    res.status(500).json({ error: 'Like operation failed' });
  }
});

// AI Assistant Routes
app.post('/api/ai/chat', isAuthenticated, async (req, res) => {
  try {
    const { message, context } = req.body;
    
    // Reset query count if it's a new day
    const today = new Date().toDateString();
    if (req.user.lastQueryDate?.toDateString() !== today) {
      req.user.aiQueriesToday = 0;
      req.user.lastQueryDate = new Date();
    }

    // Check daily limit
    if (req.user.aiQueriesToday >= 10) {
      return res.status(429).json({ error: 'Daily AI query limit reached' });
    }

    // Increment query count
    req.user.aiQueriesToday += 1;
    await req.user.save();

    // Simple response simulation (replace with actual OpenAI API)
    const responses = [
      "Here's how you can improve that code: Use async/await for better readability and error handling.",
      "The error suggests a missing dependency. Try running `npm install` to ensure all packages are installed.",
      "For better performance, consider implementing caching and optimizing your database queries.",
      "This React component could be improved with proper state management and useEffect cleanup.",
      "The MongoDB query can be optimized by adding proper indexes on the queried fields."
    ];

    const response = responses[Math.floor(Math.random() * responses.length)];
    
    res.json({ 
      response,
      queriesLeft: 10 - req.user.aiQueriesToday
    });
  } catch (error) {
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// API Marketplace Routes
app.get('/api/apis', async (req, res) => {
  try {
    const apis = await API.find();
    res.json(apis);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch APIs' });
  }
});

app.post('/api/apis/test', async (req, res) => {
  try {
    const { url, method, headers, body } = req.body;
    
    // Simple proxy for API testing
    const response = await fetch(url, {
      method: method || 'GET',
      headers: headers || {},
      body: body ? JSON.stringify(body) : undefined
    });

    const data = await response.json();
    res.json({ data, status: response.status });
  } catch (error) {
    res.status(500).json({ error: 'API test failed' });
  }
});

// Chat Routes
app.get('/api/chat/messages/:room', isAuthenticated, async (req, res) => {
  try {
    const messages = await Message.find({ room: req.params.room })
      .populate('userId', 'name')
      .sort({ timestamp: 1 })
      .limit(100);
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Jobs Routes
app.get('/api/jobs', async (req, res) => {
  try {
    const jobs = await Job.find()
      .populate('posterId', 'name email')
      .sort({ createdAt: -1 });
    res.json(jobs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch jobs' });
  }
});

app.post('/api/jobs', isAuthenticated, async (req, res) => {
  try {
    const job = new Job({
      ...req.body,
      posterId: req.user._id
    });
    await job.save();
    res.json({ message: 'Job posted', job });
  } catch (error) {
    res.status(500).json({ error: 'Job posting failed' });
  }
});

// Admin Routes
app.get('/api/admin/stats', isAdmin, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const projectCount = await Project.countDocuments();
    const jobCount = await Job.countDocuments();
    const apiUsage = await API.aggregate([{ $group: { _id: null, totalUsage: { $sum: '$usageCount' } } }]);

    res.json({
      users: userCount,
      projects: projectCount,
      jobs: jobCount,
      apiUsage: apiUsage[0]?.totalUsage || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Socket.io for real-time features
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', (room) => {
    socket.join(room);
    socket.to(room).emit('user-joined', { userId: socket.id });
  });

  socket.on('chat-message', async (data) => {
    try {
      const message = new Message({
        room: data.room,
        userId: data.userId,
        text: data.text
      });
      await message.save();
      
      const populatedMessage = await Message.findById(message._id).populate('userId', 'name');
      io.to(data.room).emit('chat-message', populatedMessage);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('typing', (data) => {
    socket.to(data.room).emit('typing', { userId: socket.id, typing: data.typing });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Database connection and server startup
async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');
    
    await initializeAPIs();
    
    const PORT = process.env.PORT || 5000;
    server.listen(PORT, () => {
      console.log(`DEVS ARENA running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
