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

// Database Models
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
  level: { type: Number, default: 1 }
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
  lastActivity: Date
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  room: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'code', 'file', 'system'], default: 'text' },
  codeLanguage: String,
  fileUrl: String,
  fileName: String,
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  reactions: Map,
  isEdited: { type: Boolean, default: false }
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
  cursors: Map
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

const apiSchema = new mongoose.Schema({
  name: String,
  description: String,
  category: String,
  endpoint: String,
  method: String,
  headers: Map,
  parameters: [{
    name: String,
    type: String,
    required: Boolean,
    description: String
  }],
  examples: [String],
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);
const CollaborationRoom = mongoose.model('CollaborationRoom', collaborationRoomSchema);
const LearningProgress = mongoose.model('LearningProgress', learningProgressSchema);
const API = mongoose.model('API', apiSchema);

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
        skills: profile._json.repos_url ? [] : []
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

// Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
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
    
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ 
          success: false, 
          message: 'Auto login failed' 
        });
      }
      res.json({ 
        success: true, 
        message: 'Registration successful!', 
        user: { 
          id: user._id, 
          username: user.username, 
          name: user.name,
          avatar: user.avatar,
          skillLevel: user.skillLevel 
        } 
      });
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
    
    // Notify about new project
    io.emit('new_project', project);
    
    res.json({ success: true, project });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create project' });
  }
});

// Real-time Chat Routes
app.get('/api/chat/rooms', async (req, res) => {
  try {
    const rooms = [
      { id: 'general', name: 'General Chat', description: 'General discussion', users: 0 },
      { id: 'javascript', name: 'JavaScript', description: 'JS/Node.js discussions', users: 0 },
      { id: 'python', name: 'Python', description: 'Python programming', users: 0 },
      { id: 'react', name: 'React', description: 'React ecosystem', users: 0 },
      { id: 'help', name: 'Help & Support', description: 'Get help with coding', users: 0 }
    ];
    
    // Get online counts for each room from socket
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
      .sort({ createdAt: 1 })
      .limit(100);
    
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

// Collaboration Rooms
app.get('/api/collaboration/rooms', async (req, res) => {
  try {
    const rooms = await CollaborationRoom.find({ isActive: true })
      .populate('owner', 'username name avatar')
      .populate('participants', 'username name avatar')
      .sort({ createdAt: -1 });
    
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
      participants: [req.user._id]
    });
    
    await room.save();
    await room.populate('owner', 'username name avatar');
    
    io.emit('new_collaboration_room', room);
    
    res.json({ success: true, room });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create room' });
  }
});

// Learning Hub Routes
app.get('/api/learning/courses', async (req, res) => {
  const courses = {
    'html': {
      title: 'HTML Fundamentals',
      description: 'Learn the foundation of web development',
      lessons: [
        { id: 'html-basics', title: 'HTML Basics', duration: '30 min', difficulty: 'Beginner' },
        { id: 'html-forms', title: 'HTML Forms', duration: '45 min', difficulty: 'Beginner' },
        { id: 'html5', title: 'HTML5 Features', duration: '60 min', difficulty: 'Intermediate' }
      ]
    },
    'css': {
      title: 'CSS Styling',
      description: 'Master the art of web design',
      lessons: [
        { id: 'css-basics', title: 'CSS Basics', duration: '40 min', difficulty: 'Beginner' },
        { id: 'css-layout', title: 'CSS Layout', duration: '50 min', difficulty: 'Intermediate' },
        { id: 'css-responsive', title: 'Responsive Design', duration: '60 min', difficulty: 'Intermediate' }
      ]
    },
    'javascript': {
      title: 'JavaScript Programming',
      description: 'Learn interactive web development',
      lessons: [
        { id: 'js-basics', title: 'JavaScript Basics', duration: '45 min', difficulty: 'Beginner' },
        { id: 'js-functions', title: 'Functions & Scope', duration: '50 min', difficulty: 'Intermediate' },
        { id: 'js-dom', title: 'DOM Manipulation', duration: '60 min', difficulty: 'Intermediate' }
      ]
    }
  };
  
  res.json({ success: true, courses });
});

// Free APIs Marketplace
app.get('/api/marketplace/apis', async (req, res) => {
  const apis = [
    {
      id: 'weather',
      name: 'Weather API',
      description: 'Get current weather and forecasts',
      category: 'Weather',
      endpoint: 'https://api.openweathermap.org/data/2.5/weather',
      method: 'GET',
      parameters: [
        { name: 'q', type: 'string', required: true, description: 'City name' },
        { name: 'appid', type: 'string', required: true, description: 'API key' }
      ]
    },
    {
      id: 'quotes',
      name: 'Inspirational Quotes',
      description: 'Get random inspirational quotes',
      category: 'Entertainment',
      endpoint: 'https://api.quotable.io/random',
      method: 'GET',
      parameters: []
    },
    {
      id: 'countries',
      name: 'REST Countries',
      description: 'Get information about countries',
      category: 'Reference',
      endpoint: 'https://restcountries.com/v3.1/all',
      method: 'GET',
      parameters: []
    }
  ];
  
  res.json({ success: true, apis });
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
    
    uploadStream.on('error', (error) => {
      res.status(500).json({ success: false, message: 'Upload failed' });
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
    
    // Enhanced AI responses
    const responses = {
      'hello': 'Hello! 👋 Welcome to DEVS ARENA! I\'m your AI coding assistant. How can I help you today?',
      'help': `I can help you with:
• **Code explanations** - Understand how code works
• **Debugging** - Find and fix errors in your code
• **Learning** - Explain programming concepts
• **Best practices** - Write better, cleaner code
• **Project ideas** - Get inspiration for your next project

What would you like help with?`,

      'html': `**HTML (HyperText Markup Language)** is the standard markup language for creating web pages.

**Key Concepts:**
• Elements and Tags
• Attributes
• Semantic HTML
• Forms and Inputs
• Accessibility

Want me to explain any specific HTML topic?`,

      'css': `**CSS (Cascading Style Sheets)** styles and layouts web pages.

**Key Features:**
• Selectors and Specificity
• Box Model
• Flexbox and Grid
• Responsive Design
• Animations and Transitions

Need help with CSS?`,

      'javascript': `**JavaScript** makes web pages interactive and dynamic.

**Core Concepts:**
• Variables and Data Types
• Functions and Scope
• DOM Manipulation
• Events
• Async/Await, Promises

What JavaScript topic are you working on?`,

      'real time chat': `DEVS ARENA has **real-time chat** with these features:

💬 **Public Rooms:**
• General Chat
• JavaScript
• Python  
• React
• Help & Support

👥 **Private Messaging**
📎 **File Sharing**
💻 **Code Snippets**
🎨 **Syntax Highlighting**

Join any room and start chatting!`,

      'collaboration': `**Real-time Collaboration Features:**

👨‍💻 **Live Code Editing**
• Multiple users can edit simultaneously
• See live cursors of other developers
• Real-time code synchronization

🎥 **Video Calls**
• Integrated video conferencing
• Screen sharing capabilities
• Voice chat

📁 **Project Sharing**
• Upload and share projects
• Collaborative coding sessions
• Version control integration

Want to start a collaboration session?`
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

// Socket.io Real-time Handlers
const activeUsers = new Map();
const userRooms = new Map();
const codeRooms = new Map();

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
    socket.to(roomId).emit('user_joined_room', {
      roomId,
      userId: activeUsers.get(socket.id),
      timestamp: new Date()
    });
    
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
        replyTo: data.replyTo
      });
      
      await message.save();
      await message.populate('user', 'username name avatar');
      await message.populate('replyTo');
      
      io.to(data.room).emit('new_message', message);
      console.log(`💬 New message in ${data.room}: ${data.content.substring(0, 50)}...`);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('💥 Message save error:', error);
    }
  });

  // Real-time code collaboration
  socket.on('join_code_room', (roomId) => {
    socket.join(roomId);
    if (!codeRooms.has(roomId)) {
      codeRooms.set(roomId, {
        code: '',
        cursors: new Map(),
        language: 'javascript'
      });
    }
    
    socket.emit('code_room_state', codeRooms.get(roomId));
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
        color: data.color
      });
      
      socket.to(data.roomId).emit('cursor_update', {
        cursors: Array.from(room.cursors.entries())
      });
    }
  });

  // Typing indicators
  socket.on('typing_start', (data) => {
    socket.to(data.room).emit('user_typing', {
      userId: data.userId,
      username: data.username,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    socket.to(data.room).emit('user_typing', {
      userId: data.userId,
      username: data.username,
      isTyping: false
    });
  });

  // Video call signaling
  socket.on('call_user', (data) => {
    socket.to(data.userToCall).emit('call_made', {
      offer: data.offer,
      socket: socket.id
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

  // Disconnection handling
  socket.on('disconnect', async () => {
    const userId = activeUsers.get(socket.id);
    
    if (userId) {
      await User.findByIdAndUpdate(userId, { isOnline: false });
      activeUsers.delete(socket.id);
      
      io.emit('users_online_update', {
        online: Array.from(activeUsers.values()).length,
        users: Array.from(activeUsers.values())
      });
    }
    
    userRooms.delete(socket.id);
    console.log('🔌 User disconnected:', socket.id);
  });
});

// Admin Routes
app.get('/api/admin/stats', async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalProjects: await Project.countDocuments(),
      totalMessages: await Message.countDocuments(),
      onlineUsers: activeUsers.size,
      activeRooms: io.sockets.adapter.rooms.size
    };
    
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('\n🚀 DEVS ARENA Server Started Successfully!');
  console.log('📍 Server URL: http://localhost:' + PORT);
  console.log('\n✅ Real-time Features Active:');
  console.log('   💬 Multi-room Chat System');
  console.log('   👥 Live User Presence');
  console.log('   💻 Real-time Code Collaboration');
  console.log('   🎥 Video Call Signaling');
  console.log('   ⌨️  Typing Indicators');
  console.log('   📁 File Upload System');
  console.log('   🤖 AI Assistant');
  console.log('   🎓 Learning Hub');
  console.log('   🛒 API Marketplace');
  console.log('\n🔧 Debug Mode: ACTIVE');
});
