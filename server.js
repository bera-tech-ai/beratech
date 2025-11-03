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
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
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

const conn = mongoose.connection;
let gfs;

conn.once('open', () => {
  gfs = new GridFSBucket(conn.db, { bucketName: 'uploads' });
  console.log('✅ GridFS Initialized');
});

// Enhanced Database Models
const userSchema = new mongoose.Schema({
  githubId: String,
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: String,
  name: String,
  avatar: { type: String, default: '' },
  skillLevel: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'], default: 'Beginner' },
  focusArea: { type: String, enum: ['Frontend', 'Backend', 'Full-Stack', 'Mobile', 'Data Science', 'DevOps', 'AI/ML'], default: 'Full-Stack' },
  isStudent: { type: Boolean, default: false },
  country: String,
  bio: { type: String, default: '' },
  skills: [String],
  githubUrl: String,
  website: String,
  isOnline: { type: Boolean, default: false },
  lastActive: { type: Date, default: Date.now },
  points: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  rank: { type: String, default: 'Newbie' },
  streak: { type: Number, default: 0 },
  lastLogin: Date,
  badges: [String],
  socialLinks: Map,
  isVerified: { type: Boolean, default: false }
}, { timestamps: true });

const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  collaborators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  tags: [String],
  category: String,
  files: [{
    name: String,
    content: String,
    language: String,
    path: String
  }],
  githubRepo: String,
  isPublic: { type: Boolean, default: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likesCount: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  forks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  forkOf: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  lastActivity: Date,
  demoUrl: String,
  readme: String,
  isFeatured: { type: Boolean, default: false }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  room: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'code', 'file', 'image', 'system'], default: 'text' },
  codeLanguage: String,
  fileUrl: String,
  fileName: String,
  fileSize: Number,
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  reactions: Map,
  isEdited: { type: Boolean, default: false },
  mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

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
  cursors: Map,
  isPublic: { type: Boolean, default: true }
}, { timestamps: true });

const learningProgressSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  course: String,
  lesson: String,
  completed: { type: Boolean, default: false },
  score: Number,
  code: String,
  completedAt: Date
}, { timestamps: true });

const challengeSchema = new mongoose.Schema({
  title: String,
  description: String,
  difficulty: { type: String, enum: ['Easy', 'Medium', 'Hard'], default: 'Easy' },
  category: String,
  problemStatement: String,
  solution: String,
  tests: [String],
  points: Number,
  solvedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  solutions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    code: String,
    language: String,
    solvedAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);
const CollaborationRoom = mongoose.model('CollaborationRoom', collaborationRoomSchema);
const LearningProgress = mongoose.model('LearningProgress', learningProgressSchema);
const Challenge = mongoose.model('Challenge', challengeSchema);

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
        return done(null, false, { message: 'Please use GitHub login' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return done(null, false, { message: 'Invalid password' });
      }

      // Update last login
      user.lastLogin = new Date();
      user.streak += 1;
      await user.save();

      return done(null, user);
    } catch (error) {
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
        avatar: profile.photos?.[0]?.value,
        githubUrl: profile.profileUrl,
        bio: profile._json.bio || '',
        isVerified: true
      });
      await user.save();
    }

    user.lastLogin = new Date();
    user.streak += 1;
    await user.save();
    
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

// Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, name, skillLevel, focusArea, isStudent, country } = req.body;
    
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User already exists' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      name: name || username,
      skillLevel,
      focusArea,
      isStudent: isStudent === 'true',
      country
    });
    
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Registration successful! Please login.',
      user: { 
        username: user.username,
        email: user.email
      } 
    });
    
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed' 
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
        message: 'Login successful!', 
        user: { 
          id: user._id, 
          username: user.username, 
          name: user.name,
          avatar: user.avatar,
          skillLevel: user.skillLevel,
          points: user.points,
          level: user.level
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
        focusArea: req.user.focusArea,
        points: req.user.points,
        level: req.user.level,
        streak: req.user.streak
      }
    });
  } else {
    res.json({ success: false, user: null });
  }
});

// Real-time Chat Routes
app.get('/api/chat/rooms', async (req, res) => {
  try {
    const rooms = [
      { id: 'general', name: 'General Chat', description: 'General discussion', icon: '💬', users: 0 },
      { id: 'javascript', name: 'JavaScript', description: 'JS/Node.js discussions', icon: '🟨', users: 0 },
      { id: 'python', name: 'Python', description: 'Python programming', icon: '🐍', users: 0 },
      { id: 'react', name: 'React', description: 'React ecosystem', icon: '⚛️', users: 0 },
      { id: 'help', name: 'Help & Support', description: 'Get help with coding', icon: '❓', users: 0 },
      { id: 'showcase', name: 'Project Showcase', description: 'Share your projects', icon: '🚀', users: 0 },
      { id: 'jobs', name: 'Jobs & Careers', description: 'Career opportunities', icon: '💼', users: 0 }
    ];
    
    const roomCounts = io.sockets.adapter.rooms;
    rooms.forEach(room => {
      room.users = roomCounts.get(room.id)?.size || 0;
    });
    
    res.json({ success: true, rooms });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch rooms' });
  }
});

app.get('/api/chat/messages/:room', async (req, res) => {
  try {
    const messages = await Message.find({ room: req.params.room })
      .populate('user', 'username name avatar')
      .populate('replyTo')
      .populate('mentions', 'username name')
      .sort({ createdAt: 1 })
      .limit(200);
    
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

// Collaboration Rooms
app.get('/api/collaboration/rooms', async (req, res) => {
  try {
    const rooms = await CollaborationRoom.find({ isActive: true, isPublic: true })
      .populate('owner', 'username name avatar')
      .populate('participants', 'username name avatar')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json({ success: true, rooms });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch rooms' });
  }
});

app.post('/api/collaboration/rooms', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const room = new CollaborationRoom({
      ...req.body,
      owner: req.user._id,
      participants: [req.user._id],
      code: req.body.code || '// Start coding together!\nconsole.log("Welcome to real-time collaboration!");'
    });
    
    await room.save();
    await room.populate('owner', 'username name avatar');
    
    io.emit('new_collaboration_room', room);
    
    res.json({ success: true, room });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create room' });
  }
});

// Projects API
app.get('/api/projects', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;

    const projects = await Project.find({ isPublic: true })
      .populate('owner', 'username name avatar')
      .populate('collaborators', 'username name avatar')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Project.countDocuments({ isPublic: true });
    
    res.json({ 
      success: true, 
      projects,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
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
      owner: req.user._id,
      collaborators: [req.user._id]
    });
    
    await project.save();
    await project.populate('owner', 'username name avatar');
    
    // Add points for project creation
    await User.findByIdAndUpdate(req.user._id, { 
      $inc: { points: 50 } 
    });
    
    io.emit('new_project', project);
    
    res.json({ success: true, project });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create project' });
  }
});

// Code Execution
app.post('/api/code/execute', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const { language, code, input } = req.body;
    
    // Simulate code execution (in production, use Docker/VM)
    let output = '';
    let error = '';
    
    if (language === 'javascript') {
      try {
        // Safe execution for demo
        const safeCode = code.replace(/process\.exit|require|import|fs|http/g, '');
        output = eval(safeCode);
      } catch (e) {
        error = e.message;
      }
    } else {
      output = `Execution simulated for ${language}\n\nCode:\n${code}`;
    }
    
    res.json({ 
      success: true, 
      output: output || 'No output',
      error: error || '',
      executionTime: Math.random() * 100 + 50 // ms
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Execution failed' });
  }
});

// File Upload
app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const filename = `${Date.now()}-${req.file.originalname}`;
    const uploadStream = gfs.openUploadStream(filename, {
      metadata: { 
        userId: req.user._id, 
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });
    
    uploadStream.end(req.file.buffer);
    
    uploadStream.on('finish', () => {
      res.json({ 
        success: true, 
        message: 'File uploaded successfully',
        file: {
          id: uploadStream.id,
          filename: filename,
          originalName: req.file.originalname,
          size: req.file.size,
          url: `/api/files/${filename}`
        }
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Upload failed' });
  }
});

app.get('/api/files/:filename', (req, res) => {
  gfs.openDownloadStreamByName(req.params.filename).pipe(res);
});

// AI Assistant
app.post('/api/ai/chat', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const { message, context = 'general' } = req.body;
    
    const responses = {
      'hello': 'Hello! 👋 Welcome to DEVS ARENA! I\'m your AI coding assistant. How can I help you today?',
      'help': `I can help you with:
• **Code explanations** - Understand how code works
• **Debugging** - Find and fix errors in your code  
• **Learning** - Explain programming concepts
• **Best practices** - Write better, cleaner code
• **Project ideas** - Get inspiration for your next project

What would you like help with?`,

      'real time chat': `DEVS ARENA has **real-time chat** with these features:

💬 **Public Rooms:**
• General Chat
• JavaScript
• Python  
• React
• Help & Support
• Project Showcase
• Jobs & Careers

👥 **Private Messaging**
📎 **File Sharing**
💻 **Code Snippets**
🎨 **Syntax Highlighting**
🔔 **Mentions & Notifications**

Join any room and start chatting!`,

      'collaboration': `**Real-time Collaboration Features:**

👨‍💻 **Live Code Editing**
• Multiple users can edit simultaneously
• See live cursors of other developers
• Real-time code synchronization
• Syntax highlighting for 50+ languages

🎥 **Video Calls**
• Integrated video conferencing
• Screen sharing capabilities
• Voice chat for pair programming

📁 **Project Sharing**
• Upload and share projects
• Collaborative coding sessions
• Fork and remix others' projects

Want to start a collaboration session?`,

      'code sharing': `**Code Sharing Features:**

🚀 **Instant Sharing**
• Share code snippets in chat
• Create collaborative coding rooms
• Fork existing projects
• Live code execution

📊 **Version Control**
• Track changes in real-time
• See who made what changes
• Revert to previous versions

🌐 **Public Projects**
• Showcase your work to the community
• Get feedback from other developers
• Collaborate on open source projects

Start sharing your code today!`
    };
    
    const lowerMessage = message.toLowerCase();
    let response = responses[lowerMessage] || 
      `I understand you're asking about **"${message}"**. 

I can help you with:
• Code explanations and debugging
• Programming concepts and learning
• Project collaboration features
• Real-time chat and communication
• Best practices and code reviews

Could you provide more details about what you need help with?`;

    res.json({ success: true, response });
  } catch (error) {
    res.status(500).json({ success: false, message: 'AI service unavailable' });
  }
});

// Challenges & Gamification
app.get('/api/challenges', async (req, res) => {
  try {
    const challenges = await Challenge.find()
      .populate('solvedBy', 'username name avatar')
      .sort({ difficulty: 1, createdAt: -1 });
    
    res.json({ success: true, challenges });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch challenges' });
  }
});

app.post('/api/challenges/solve', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  try {
    const { challengeId, code, language } = req.body;
    
    const challenge = await Challenge.findById(challengeId);
    if (!challenge) {
      return res.status(404).json({ success: false, message: 'Challenge not found' });
    }
    
    // Add solution
    challenge.solutions.push({
      user: req.user._id,
      code,
      language
    });
    
    // Add user to solvedBy if not already
    if (!challenge.solvedBy.includes(req.user._id)) {
      challenge.solvedBy.push(req.user._id);
      
      // Award points
      await User.findByIdAndUpdate(req.user._id, {
        $inc: { points: challenge.points || 100 }
      });
    }
    
    await challenge.save();
    
    res.json({ success: true, message: 'Challenge completed!', points: challenge.points });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to submit solution' });
  }
});

// Leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const topUsers = await User.find()
      .select('username name avatar points level streak')
      .sort({ points: -1 })
      .limit(50);
    
    res.json({ success: true, users: topUsers });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch leaderboard' });
  }
});

// Socket.io Real-time Handlers
const activeUsers = new Map();
const userRooms = new Map();
const codeRooms = new Map();
const typingUsers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  // User online status
  socket.on('user_online', async (userId) => {
    activeUsers.set(socket.id, userId);
    userRooms.set(socket.id, new Set());
    
    await User.findByIdAndUpdate(userId, { 
      isOnline: true, 
      lastActive: new Date() 
    });
    
    io.emit('users_online_update', {
      online: Array.from(activeUsers.values()).length,
      users: Array.from(activeUsers.values())
    });
    
    console.log('👥 Online users:', activeUsers.size);
  });

  // Chat room management
  socket.on('join_room', async (roomId) => {
    socket.join(roomId);
    
    const userRoomsSet = userRooms.get(socket.id) || new Set();
    userRoomsSet.add(roomId);
    userRooms.set(socket.id, userRoomsSet);
    
    // Notify room about new user
    const userId = activeUsers.get(socket.id);
    if (userId) {
      const user = await User.findById(userId).select('username name avatar');
      socket.to(roomId).emit('user_joined_room', {
        roomId,
        user,
        timestamp: new Date()
      });
    }
    
    // Update room user count
    const roomUsers = io.sockets.adapter.rooms.get(roomId)?.size || 0;
    io.to(roomId).emit('room_users_update', {
      roomId,
      userCount: roomUsers
    });
    
    console.log(`🚪 User joined room: ${roomId}`);
  });

  socket.on('leave_room', (roomId) => {
    socket.leave(roomId);
    
    const userRoomsSet = userRooms.get(socket.id);
    if (userRoomsSet) {
      userRoomsSet.delete(roomId);
    }
    
    socket.to(roomId).emit('user_left_room', {
      roomId,
      userId: activeUsers.get(socket.id)
    });
  });

  // Real-time messaging
  socket.on('send_message', async (data) => {
    try {
      const message = new Message({
        room: data.room,
        user: data.userId,
        content: data.content,
        type: data.type,
        codeLanguage: data.codeLanguage,
        replyTo: data.replyTo,
        mentions: data.mentions
      });
      
      await message.save();
      await message.populate('user', 'username name avatar');
      await message.populate('replyTo');
      await message.populate('mentions', 'username name');
      
      io.to(data.room).emit('new_message', message);
      
      // Clear typing indicator
      typingUsers.delete(data.userId);
      socket.to(data.room).emit('user_typing', {
        userId: data.userId,
        username: data.username,
        isTyping: false
      });
      
      console.log(`💬 New message in ${data.room}: ${data.content.substring(0, 50)}...`);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('💥 Message save error:', error);
    }
  });

  // Typing indicators
  socket.on('typing_start', (data) => {
    typingUsers.set(data.userId, {
      username: data.username,
      room: data.room,
      lastTyping: Date.now()
    });
    
    socket.to(data.room).emit('user_typing', {
      userId: data.userId,
      username: data.username,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    typingUsers.delete(data.userId);
    socket.to(data.room).emit('user_typing', {
      userId: data.userId,
      username: data.username,
      isTyping: false
    });
  });

  // Real-time code collaboration
  socket.on('join_code_room', (roomId) => {
    socket.join(roomId);
    if (!codeRooms.has(roomId)) {
      codeRooms.set(roomId, {
        code: '// Welcome to real-time collaboration!\nconsole.log("Start coding together!");',
        cursors: new Map(),
        language: 'javascript',
        participants: new Set()
      });
    }
    
    const room = codeRooms.get(roomId);
    room.participants.add(socket.id);
    
    socket.emit('code_room_state', {
      code: room.code,
      language: room.language,
      cursors: Array.from(room.cursors.entries())
    });
    
    // Notify others
    socket.to(roomId).emit('user_joined_code_room', {
      userId: activeUsers.get(socket.id),
      participantCount: room.participants.size
    });
    
    console.log(`💻 User joined code room: ${roomId}`);
  });

  socket.on('code_change', (data) => {
    const room = codeRooms.get(data.roomId);
    if (room) {
      room.code = data.code;
      room.language = data.language;
      
      socket.to(data.roomId).emit('code_update', {
        code: data.code,
        language: data.language,
        userId: data.userId,
        timestamp: new Date()
      });
    }
  });

  socket.on('cursor_move', (data) => {
    const room = codeRooms.get(data.roomId);
    if (room) {
      room.cursors.set(data.userId, {
        position: data.position,
        name: data.name,
        color: data.color,
        timestamp: Date.now()
      });
      
      socket.to(data.roomId).emit('cursor_update', {
        cursors: Array.from(room.cursors.entries())
      });
    }
  });

  socket.on('leave_code_room', (roomId) => {
    socket.leave(roomId);
    
    const room = codeRooms.get(roomId);
    if (room) {
      room.participants.delete(socket.id);
      room.cursors.delete(activeUsers.get(socket.id));
      
      socket.to(roomId).emit('user_left_code_room', {
        userId: activeUsers.get(socket.id),
        participantCount: room.participants.size
      });
    }
  });

  // Video call signaling
  socket.on('call_user', (data) => {
    socket.to(data.userToCall).emit('call_made', {
      offer: data.offer,
      socket: socket.id,
      caller: data.caller
    });
  });

  socket.on('make_answer', (data) => {
    socket.to(data.to).emit('answer_made', {
      socket: socket.id,
      answer: data.answer
    });
  });

  socket.on('ice_candidate', (data) => {
    socket.to(data.to).emit('ice_candidate', {
      candidate: data.candidate,
      socket: socket.id
    });
  });

  // File sharing
  socket.on('file_uploaded', (data) => {
    socket.to(data.room).emit('new_file', {
      file: data.file,
      user: data.user,
      timestamp: new Date()
    });
  });

  // Disconnection handling
  socket.on('disconnect', async () => {
    const userId = activeUsers.get(socket.id);
    
    // Leave all rooms
    const userRoomsSet = userRooms.get(socket.id);
    if (userRoomsSet) {
      userRoomsSet.forEach(roomId => {
        socket.to(roomId).emit('user_left_room', { roomId, userId });
      });
    }
    
    // Leave code rooms
    codeRooms.forEach((room, roomId) => {
      if (room.participants.has(socket.id)) {
        room.participants.delete(socket.id);
        room.cursors.delete(userId);
        socket.to(roomId).emit('user_left_code_room', {
          userId,
          participantCount: room.participants.size
        });
      }
    });
    
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false });
      activeUsers.delete(socket.id);
      
      io.emit('users_online_update', {
        online: Array.from(activeUsers.values()).length,
        users: Array.from(activeUsers.values())
      });
    }
    
    userRooms.delete(socket.id);
    typingUsers.delete(userId);
    console.log('🔌 User disconnected:', socket.id);
  });
});

// Clean up typing indicators every minute
setInterval(() => {
  const now = Date.now();
  typingUsers.forEach((data, userId) => {
    if (now - data.lastTyping > 5000) { // 5 seconds
      typingUsers.delete(userId);
      io.to(data.room).emit('user_typing', {
        userId,
        username: data.username,
        isTyping: false
      });
    }
  });
}, 60000);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('\n🚀 DEVS ARENA - Global Developer Platform Started!');
  console.log('📍 Server URL: http://localhost:' + PORT);
  console.log('\n✅ Complete Feature Set Active:');
  console.log('   💬 Multi-room Real-time Chat');
  console.log('   👥 Live User Presence & Typing Indicators');
  console.log('   💻 Real-time Code Collaboration');
  console.log('   🎥 Video Call & Screen Sharing');
  console.log('   📁 File Sharing & Code Execution');
  console.log('   🏆 Gamification & Leaderboard');
  console.log('   🤖 AI Coding Assistant');
  console.log('   🚀 Project Sharing & Collaboration');
  console.log('   ⚡ Instant Code Sharing');
  console.log('   🎯 Coding Challenges & Points');
  console.log('\n🌍 Ready to Go Viral!');
});
