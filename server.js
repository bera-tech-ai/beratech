import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { GridFSBucket } from 'mongodb';
import OpenAI from 'openai';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import { body, validationResult } from 'express-validator';
import cron from 'node-cron';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.tailwindcss.com", "cdn.socket.io", "unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdn.tailwindcss.com", "fonts.googleapis.com"],
      fontSrc: ["'self'", "fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:", "*.socket.io", "api.openai.com"]
    }
  }
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100
});
app.use(limiter);

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'devs-arena-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection & Models
await mongoose.connect(process.env.MONGODB_URI);
const conn = mongoose.connection;

let gfs;
conn.once('open', () => {
  gfs = new GridFSBucket(conn.db, { bucketName: 'uploads' });
});

// Enhanced User Schema
const userSchema = new mongoose.Schema({
  githubId: String,
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: String,
  name: String,
  avatar: String,
  skillLevel: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'], default: 'Beginner' },
  focusArea: { type: String, enum: ['Frontend', 'Backend', 'Full-Stack', 'Mobile', 'Data Science', 'DevOps', 'AI/ML'] },
  isStudent: Boolean,
  isProfessional: Boolean,
  country: String,
  bio: String,
  githubUrl: String,
  website: String,
  skills: [String],
  badges: [String],
  points: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  learningProgress: Map,
  completedLessons: [String],
  lastActive: Date,
  isOnline: { type: Boolean, default: false }
}, { timestamps: true });

// Enhanced Project Schema
const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  collaborators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  tags: [String],
  category: String,
  files: [{
    filename: String,
    originalName: String,
    content: String,
    language: String,
    size: Number,
    uploadDate: { type: Date, default: Date.now }
  }],
  githubRepo: String,
  isPublic: { type: Boolean, default: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likesCount: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  forks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  forkOf: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  lastActivity: Date,
  readme: String,
  deploymentUrl: String
}, { timestamps: true });

// Enhanced Message Schema
const messageSchema = new mongoose.Schema({
  room: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: String,
  type: { type: String, enum: ['text', 'code', 'file', 'system'], default: 'text' },
  codeLanguage: String,
  fileUrl: String,
  fileName: String,
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  reactions: Map,
  isEdited: { type: Boolean, default: false }
}, { timestamps: true });

// New Code Execution Schema
const codeExecutionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  language: { type: String, required: true },
  code: { type: String, required: true },
  input: String,
  output: String,
  error: String,
  executionTime: Number,
  memoryUsed: Number,
  status: { type: String, enum: ['success', 'error', 'timeout'], default: 'success' }
}, { timestamps: true });

// New Collaboration Room Schema
const collaborationRoomSchema = new mongoose.Schema({
  name: String,
  description: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  isActive: { type: Boolean, default: true },
  maxParticipants: { type: Number, default: 10 },
  currentFile: String,
  language: String,
  code: String,
  cursors: Map
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);
const CodeExecution = mongoose.model('CodeExecution', codeExecutionSchema);
const CollaborationRoom = mongoose.model('CollaborationRoom', collaborationRoomSchema);

// Passport Configuration
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ $or: [{ email: username }, { username: username }] });
    if (!user) return done(null, false, { message: 'User not found' });
    
    if (user.password && await bcrypt.compare(password, user.password)) {
      return done(null, user);
    }
    return done(null, false, { message: 'Invalid password' });
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
        username: profile.username,
        email: profile.emails?.[0]?.value,
        name: profile.displayName,
        avatar: profile.photos?.[0]?.value,
        githubUrl: profile.profileUrl
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

// Multer Configuration for File Uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    // Allow all file types
    cb(null, true);
  }
});

// OpenAI Configuration
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Serve Static Files & Frontend
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// Authentication Routes
app.post('/auth/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('username').isAlphanumeric().isLength({ min: 3 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { username, email, password, name, skillLevel, focusArea, isStudent, country } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      username, email, password: hashedPassword, name, skillLevel, focusArea, isStudent, country
    });
    await user.save();
    
    req.login(user, (err) => {
      if (err) return res.status(500).json({ error: 'Login failed after registration' });
      res.json({ message: 'Registration successful', user: { id: user._id, username: user.username } });
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', passport.authenticate('local'), (req, res) => {
  res.json({ message: 'Login successful', user: req.user });
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { 
  failureRedirect: '/?auth=failed' 
}), (req, res) => {
  res.redirect('/');
});

app.post('/auth/logout', (req, res) => {
  req.logout(() => {
    res.json({ message: 'Logout successful' });
  });
});

// File Upload Routes
app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const filename = `${Date.now()}-${req.file.originalname}`;
    const uploadStream = gfs.openUploadStream(filename, {
      metadata: { userId: req.user._id, originalName: req.file.originalname }
    });
    
    uploadStream.end(req.file.buffer);
    uploadStream.on('finish', () => {
      res.json({ 
        message: 'File uploaded successfully', 
        fileId: uploadStream.id,
        filename: filename,
        originalName: req.file.originalname
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/files/:filename', (req, res) => {
  gfs.openDownloadStreamByName(req.params.filename).pipe(res);
});

// Project Routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find({ isPublic: true })
      .populate('owner', 'username name avatar')
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.post('/api/projects', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const project = new Project({
      ...req.body,
      owner: req.user._id,
      collaborators: [req.user._id]
    });
    await project.save();
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// AI Assistant Route
app.post('/api/ai/chat', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const { message, context = 'general' } = req.body;
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: `You are an AI coding assistant for DEVS ARENA. Help with ${context} related questions. Be concise and helpful.`
        },
        { role: "user", content: message }
      ],
      max_tokens: 500
    });
    
    res.json({ response: completion.choices[0].message.content });
  } catch (error) {
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// Code Execution Route (Enhanced)
app.post('/api/code/execute', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const { language, code, input } = req.body;
    
    // Simulate code execution (in production, use Docker or external service)
    const execution = new CodeExecution({
      user: req.user._id,
      language,
      code,
      input,
      output: `Execution result for ${language} code`,
      executionTime: Math.random() * 1000,
      memoryUsed: Math.random() * 50
    });
    await execution.save();
    
    res.json({
      output: execution.output,
      executionTime: execution.executionTime,
      memoryUsed: execution.memoryUsed
    });
  } catch (error) {
    res.status(500).json({ error: 'Code execution failed' });
  }
});

// Collaboration Routes
app.post('/api/collaboration/rooms', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const room = new CollaborationRoom({
      ...req.body,
      owner: req.user._id,
      participants: [req.user._id]
    });
    await room.save();
    res.json(room);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Admin Routes
app.get('/admin', (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Admin dashboard data
  res.json({ message: 'Admin access granted' });
});

// Real-time Socket.io Handlers
const activeUsers = new Map();
const codeRooms = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user_online', async (userId) => {
    activeUsers.set(socket.id, userId);
    await User.findByIdAndUpdate(userId, { isOnline: true, lastActive: new Date() });
    io.emit('users_online', Array.from(activeUsers.values()));
  });

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    socket.to(roomId).emit('user_joined', socket.id);
  });

  socket.on('code_change', (data) => {
    socket.to(data.roomId).emit('code_update', {
      code: data.code,
      userId: data.userId,
      cursor: data.cursor
    });
  });

  socket.on('cursor_move', (data) => {
    socket.to(data.roomId).emit('cursor_update', {
      userId: data.userId,
      cursor: data.cursor,
      name: data.name
    });
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
      
      io.to(data.room).emit('new_message', await message.populate('user', 'username name avatar'));
    } catch (error) {
      socket.emit('error', 'Failed to send message');
    }
  });

  socket.on('disconnect', async () => {
    const userId = activeUsers.get(socket.id);
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false });
      activeUsers.delete(socket.id);
      io.emit('users_online', Array.from(activeUsers.values()));
    }
    console.log('User disconnected:', socket.id);
  });
});

// Background Jobs
cron.schedule('0 0 * * *', async () => {
  // Daily cleanup of inactive collaboration rooms
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  await CollaborationRoom.updateMany(
    { lastActivity: { $lt: cutoff }, isActive: true },
    { isActive: false }
  );
  console.log('Cleaned up inactive collaboration rooms');
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`DEVS ARENA running on port ${PORT}`);
});
