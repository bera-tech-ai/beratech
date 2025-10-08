// server.js - COMPLETE REAL-TIME FUNCTIONALITY
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const { OpenAI } = require('openai');
const cors = require('cors');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static('uploads'));
app.use(require('express-session')({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.log('❌ MongoDB Error:', err));

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// MongoDB Schemas (same as before, but ensure they're properly defined)
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['Frontend', 'Backend', 'Full-stack', 'Designer', 'Student', 'Mentor', 'Other'], default: 'Other' },
  level: { type: String, enum: ['Beginner', 'Intermediate', 'Pro'], default: 'Beginner' },
  skills: [String],
  country: String,
  bio: String,
  avatar: String,
  reputation: { type: Number, default: 0 },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  githubId: String,
  isVerified: { type: Boolean, default: false },
  badges: [String],
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  githubLink: String,
  liveLink: String,
  tags: [String],
  screenshot: String,
  codeFiles: [{
    filename: String,
    content: String,
    language: String
  }],
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  forks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  viewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const APISchema = new mongoose.Schema({
  name: { type: String, required: true },
  endpoint: { type: String, required: true },
  method: { type: String, enum: ['GET', 'POST', 'PUT', 'DELETE'], default: 'GET' },
  description: String,
  category: String,
  parameters: [{
    name: String,
    type: String,
    required: Boolean,
    description: String
  }],
  response: mongoose.Schema.Types.Mixed,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isApproved: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  room: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: String,
  type: { type: String, enum: ['text', 'code', 'file'], default: 'text' },
  fileUrl: String,
  codeLanguage: String,
  isEdited: { type: Boolean, default: false },
  reactions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const LessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  content: String,
  category: { type: String, required: true },
  level: { type: String, enum: ['Beginner', 'Intermediate', 'Advanced'], required: true },
  duration: Number,
  videoUrl: String,
  codeExamples: [{
    title: String,
    code: String,
    language: String,
    explanation: String
  }],
  quiz: [{
    question: String,
    options: [String],
    answer: String,
    explanation: String
  }],
  order: Number,
  isPublished: { type: Boolean, default: false }
});

const UserProgressSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  lesson: { type: mongoose.Schema.Types.ObjectId, ref: 'Lesson', required: true },
  completed: { type: Boolean, default: false },
  score: Number,
  timeSpent: Number,
  lastAccessed: { type: Date, default: Date.now }
});

const HackathonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  submissions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    submittedAt: { type: Date, default: Date.now },
    score: Number
  }],
  winners: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isActive: { type: Boolean, default: true },
  prize: String
});

// MongoDB Models
const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const API = mongoose.model('API', APISchema);
const Message = mongoose.model('Message', MessageSchema);
const Lesson = mongoose.model('Lesson', LessonSchema);
const UserProgress = mongoose.model('UserProgress', UserProgressSchema);
const Hackathon = mongoose.model('Hackathon', HackathonSchema);

// Store online users
const onlineUsers = new Map();

// Multer Configuration for File Uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, level, skills, country, bio } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'Other',
      level: level || 'Beginner',
      skills: skills || [],
      country,
      bio
    });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        role: user.role,
        level: user.level,
        avatar: user.avatar
      } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        role: user.role,
        level: user.level,
        avatar: user.avatar,
        reputation: user.reputation
      } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password')
      .populate('followers', 'name avatar')
      .populate('following', 'name avatar');
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Chat Routes
app.get('/api/messages/:room', async (req, res) => {
  try {
    const messages = await Message.find({ room: req.params.room })
      .populate('user', 'name avatar')
      .sort({ createdAt: 1 })
      .limit(100);
    
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project Routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find()
      .populate('author', 'name avatar')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', authenticateToken, upload.single('screenshot'), async (req, res) => {
  try {
    const { title, description, githubLink, liveLink, tags } = req.body;
    
    if (!title) {
      return res.status(400).json({ error: 'Project title is required' });
    }

    const project = await Project.create({
      title,
      description,
      githubLink,
      liveLink,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      screenshot: req.file ? `/uploads/${req.file.filename}` : null,
      author: req.user._id
    });

    const populatedProject = await Project.findById(project._id)
      .populate('author', 'name avatar role level');

    // Broadcast new project to all connected clients
    io.emit('new-project', populatedProject);

    res.json(populatedProject);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects/:id/like', authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const hasLiked = project.likes.includes(req.user._id);
    
    if (hasLiked) {
      project.likes = project.likes.filter(like => !like.equals(req.user._id));
    } else {
      project.likes.push(req.user._id);
    }

    await project.save();

    // Broadcast like update
    io.emit('project-updated', {
      projectId: project._id,
      likes: project.likes.length,
      liked: !hasLiked
    });

    res.json({ likes: project.likes.length, liked: !hasLiked });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API Hub Routes
app.get('/api/apis', async (req, res) => {
  try {
    const apis = await API.find({ isApproved: true })
      .populate('owner', 'name avatar')
      .sort({ usageCount: -1 });
    
    res.json(apis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/apis/test', authenticateToken, async (req, res) => {
  try {
    const { endpoint, method = 'GET', body } = req.body;
    
    // Simulate API call
    const mockResponses = {
      '/api/weather/london': {
        city: 'London',
        temperature: '15°C',
        conditions: 'Partly Cloudy',
        humidity: '65%'
      },
      '/api/users': {
        users: [
          { id: 1, name: 'John Doe', email: 'john@example.com' },
          { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
        ],
        total: 2
      },
      '/api/projects': {
        projects: [
          { id: 1, title: 'Chat App', description: 'Real-time chat application' },
          { id: 2, title: 'E-commerce', description: 'Online shopping platform' }
        ]
      }
    };

    const response = mockResponses[endpoint] || { 
      error: 'Endpoint not found in test environment',
      availableEndpoints: Object.keys(mockResponses)
    };

    // Increment usage count
    const api = await API.findOne({ endpoint });
    if (api) {
      api.usageCount += 1;
      await api.save();
    }

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// AI Assistant Route
app.post('/api/ai/assist', authenticateToken, async (req, res) => {
  try {
    const { prompt, mode = 'code_generation', language = 'javascript' } = req.body;
    
    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // If no OpenAI API key, return mock response
    if (!process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY === 'your_openai_api_key_here') {
      const mockResponses = {
        code_generation: `// Generated ${language} code for: ${prompt}\nfunction solution() {\n  // Your code here\n  return "Implementation for: ${prompt}"\n}`,
        debug: `// Debugging: ${prompt}\n// Issue identified and fixed\n// Original code had syntax error, now corrected`,
        explain: `Explanation: ${prompt}\nThis code demonstrates how to implement the requested functionality with proper best practices.`,
        learn: `Learning: ${prompt}\nLet me break this down step by step...`
      };
      
      return res.json({ 
        response: mockResponses[mode] || `AI Response for: ${prompt}`,
        mode,
        timestamp: new Date().toISOString()
      });
    }

    let systemMessage = '';
    switch (mode) {
      case 'code_generation':
        systemMessage = `You are an expert programming assistant. Generate clean, efficient ${language} code based on the user request. Include comments and best practices.`;
        break;
      case 'debug':
        systemMessage = 'You are a debugging expert. Analyze the provided code, identify issues, and provide fixed code with explanations.';
        break;
      case 'explain':
        systemMessage = 'You are a programming educator. Explain the provided code or concept in simple terms with examples.';
        break;
      case 'learn':
        systemMessage = 'You are a patient programming mentor. Break down concepts into digestible parts with practical examples.';
        break;
      default:
        systemMessage = 'You are a helpful programming assistant.';
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: systemMessage },
        { role: "user", content: prompt }
      ],
      max_tokens: 1500,
      temperature: 0.7
    });

    const response = completion.choices[0].message.content;

    res.json({ 
      response,
      mode,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('OpenAI Error:', error);
    res.status(500).json({ 
      error: 'AI service temporarily unavailable. Please try again later.',
      fallback: `Here's a basic implementation for: ${req.body.prompt}`
    });
  }
});

// Lessons Routes
app.get('/api/lessons', async (req, res) => {
  try {
    const lessons = await Lesson.find({ isPublished: true })
      .sort({ order: 1, createdAt: 1 });
    
    res.json(lessons);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/lessons/:id', async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id);
    if (!lesson) {
      return res.status(404).json({ error: 'Lesson not found' });
    }
    res.json(lesson);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/lessons/:id/progress', authenticateToken, async (req, res) => {
  try {
    const { completed, score, timeSpent } = req.body;
    
    const progress = await UserProgress.findOneAndUpdate(
      { user: req.user._id, lesson: req.params.id },
      { 
        completed: completed || false,
        score: score || 0,
        timeSpent: timeSpent || 0,
        lastAccessed: new Date()
      },
      { upsert: true, new: true }
    );

    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Real-time Socket.IO Implementation
io.on('connection', (socket) => {
  console.log('🔗 User connected:', socket.id);

  socket.on('user-online', async (userData) => {
    try {
      onlineUsers.set(socket.id, userData.userId);
      
      await User.findByIdAndUpdate(userData.userId, {
        isOnline: true,
        lastSeen: new Date()
      });

      // Broadcast updated online users list
      const onlineUsersList = await User.find({ 
        _id: { $in: Array.from(onlineUsers.values()) },
        isOnline: true 
      }).select('name avatar role level');

      io.emit('online-users-update', onlineUsersList);
      console.log(`👤 User ${userData.userId} is now online`);
    } catch (error) {
      console.error('Error setting user online:', error);
    }
  });

  socket.on('join-room', (room) => {
    socket.join(room);
    console.log(`🚪 User ${socket.id} joined room: ${room}`);
  });

  socket.on('send-message', async (data) => {
    try {
      const message = await Message.create({
        room: data.room,
        user: data.userId,
        text: data.text,
        type: data.type,
        codeLanguage: data.codeLanguage
      });

      const populatedMessage = await Message.findById(message._id)
        .populate('user', 'name avatar role level');

      // Send to all users in the room
      io.to(data.room).emit('new-message', populatedMessage);
      
      console.log(`💬 New message in ${data.room} from ${data.userId}`);
    } catch (error) {
      console.error('Error saving message:', error);
      socket.emit('message-error', { error: 'Failed to send message' });
    }
  });

  socket.on('typing-start', (data) => {
    socket.to(data.room).emit('user-typing', {
      userId: data.userId,
      userName: data.userName,
      isTyping: true
    });
  });

  socket.on('typing-stop', (data) => {
    socket.to(data.room).emit('user-typing', {
      userId: data.userId,
      userName: data.userName,
      isTyping: false
    });
  });

  socket.on('disconnect', async () => {
    try {
      const userId = onlineUsers.get(socket.id);
      
      if (userId) {
        onlineUsers.delete(socket.id);
        
        await User.findByIdAndUpdate(userId, {
          isOnline: false,
          lastSeen: new Date()
        });

        // Broadcast updated online users list
        const onlineUsersList = await User.find({ 
          _id: { $in: Array.from(onlineUsers.values()) },
          isOnline: true 
        }).select('name avatar role level');

        io.emit('online-users-update', onlineUsersList);
        console.log(`👤 User ${userId} disconnected`);
      }
    } catch (error) {
      console.error('Error handling disconnect:', error);
    }
  });
});

// Initialize Sample Data
async function initializeSampleData() {
  try {
    // Sample Lessons
    const lessonCount = await Lesson.countDocuments();
    if (lessonCount === 0) {
      const sampleLessons = [
        {
          title: 'HTML Fundamentals',
          description: 'Learn the basics of HTML structure and tags',
          category: 'Web Development',
          level: 'Beginner',
          content: 'HTML is the standard markup language for creating web pages...',
          codeExamples: [
            {
              title: 'Basic HTML Structure',
              code: `<!DOCTYPE html>
<html>
<head>
    <title>My First Page</title>
</head>
<body>
    <h1>Hello World!</h1>
    <p>This is my first web page.</p>
</body>
</html>`,
              language: 'html',
              explanation: 'This shows the basic structure of every HTML document.'
            }
          ],
          order: 1,
          isPublished: true
        },
        {
          title: 'CSS Styling',
          description: 'Learn how to style your web pages with CSS',
          category: 'Web Development',
          level: 'Beginner',
          content: 'CSS is used to control the presentation of web pages...',
          order: 2,
          isPublished: true
        },
        {
          title: 'JavaScript Basics',
          description: 'Introduction to JavaScript programming',
          category: 'Web Development',
          level: 'Beginner',
          content: 'JavaScript makes web pages interactive and dynamic...',
          order: 3,
          isPublished: true
        }
      ];
      
      await Lesson.insertMany(sampleLessons);
      console.log('✅ Sample lessons created');
    }

    // Sample APIs
    const apiCount = await API.countDocuments();
    if (apiCount === 0) {
      let adminUser = await User.findOne({ email: 'admin@devsarena.com' });
      if (!adminUser) {
        adminUser = await User.create({
          name: 'Devs Arena Admin',
          email: 'admin@devsarena.com',
          password: await bcrypt.hash('admin123', 12),
          role: 'Full-stack',
          level: 'Pro',
          isVerified: true
        });
      }

      const sampleAPIs = [
        {
          name: 'Weather API',
          endpoint: '/api/weather/{city}',
          method: 'GET',
          description: 'Get current weather information for any city',
          category: 'Weather',
          owner: adminUser._id,
          isApproved: true
        },
        {
          name: 'User Management API',
          endpoint: '/api/users',
          method: 'GET',
          description: 'Get list of users',
          category: 'Authentication',
          owner: adminUser._id,
          isApproved: true
        },
        {
          name: 'Projects API',
          endpoint: '/api/projects',
          method: 'GET',
          description: 'Get all projects',
          category: 'Projects',
          owner: adminUser._id,
          isApproved: true
        }
      ];
      
      await API.insertMany(sampleAPIs);
      console.log('✅ Sample APIs created');
    }

    // Sample Projects
    const projectCount = await Project.countDocuments();
    if (projectCount === 0 && adminUser) {
      const sampleProjects = [
        {
          title: 'Real-time Chat Application',
          description: 'A modern chat app built with Socket.IO and React',
          githubLink: 'https://github.com/example/chat-app',
          liveLink: 'https://chat-app.example.com',
          tags: ['React', 'Socket.IO', 'Node.js', 'Real-time'],
          author: adminUser._id
        },
        {
          title: 'E-commerce Platform',
          description: 'Full-stack e-commerce solution with payment integration',
          githubLink: 'https://github.com/example/ecommerce',
          tags: ['MERN', 'Stripe', 'MongoDB', 'Express'],
          author: adminUser._id
        }
      ];
      
      await Project.insertMany(sampleProjects);
      console.log('✅ Sample projects created');
    }
  } catch (error) {
    console.error('Error initializing sample data:', error);
  }
}

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
  console.log(`🚀 DEVS ARENA Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV}`);
  
  // Initialize sample data
  await initializeSampleData();
});
