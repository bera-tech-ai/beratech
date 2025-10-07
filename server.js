const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const OpenAI = require('openai');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/devsarena', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  role: { type: String, enum: ['frontend', 'backend', 'fullstack', 'designer', 'student', 'mentor', 'other'] },
  level: { type: String, enum: ['beginner', 'intermediate', 'pro'] },
  skills: [String],
  country: String,
  bio: String,
  avatar: String,
  reputation: { type: Number, default: 0 },
  projectsCount: { type: Number, default: 0 },
  followersCount: { type: Number, default: 0 },
  followingCount: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  githubId: String,
  createdAt: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  githubLink: String,
  liveLink: String,
  tags: [String],
  screenshot: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  likes: { type: Number, default: 0 },
  comments: { type: Number, default: 0 },
  forks: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  room: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  message: String,
  type: { type: String, default: 'text' },
  createdAt: { type: Date, default: Date.now }
});

const apiSchema = new mongoose.Schema({
  name: String,
  endpoint: String,
  description: String,
  category: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isApproved: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 }
});

// Models
const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);
const API = mongoose.model('API', apiSchema);

// Multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});
const upload = multer({ storage: storage });

// OpenAI initialization
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, level, skills, country, bio } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role,
      level,
      skills: skills ? skills.split(',').map(skill => skill.trim()) : [],
      country,
      bio
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
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
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

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
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Auth me error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password')
      .populate('projects', 'title description');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
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
    console.error('Projects error:', error);
    res.status(500).json({ message: 'Server error fetching projects' });
  }
});

app.post('/api/projects', authenticateToken, upload.single('screenshot'), async (req, res) => {
  try {
    const { title, description, githubLink, liveLink, tags } = req.body;
    
    const project = new Project({
      title,
      description,
      githubLink,
      liveLink,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      screenshot: req.file ? `/uploads/${req.file.filename}` : null,
      author: req.user.userId
    });

    await project.save();

    // Update user's project count
    await User.findByIdAndUpdate(req.user.userId, { $inc: { projectsCount: 1 } });

    res.status(201).json(project);
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ message: 'Server error creating project' });
  }
});

// AI Routes
app.post('/api/ai/generate-code', authenticateToken, async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt) {
      return res.status(400).json({ message: 'Prompt is required' });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: "You are an expert programming assistant. Generate clean, efficient, and well-commented code based on the user's request. Always return only the code without additional explanations unless specifically asked."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 1000
    });

    const code = completion.choices[0].message.content;
    res.json({ code });
  } catch (error) {
    console.error('AI error:', error);
    res.status(500).json({ message: 'Error generating code with AI' });
  }
});

// API Hub Routes
app.get('/api/apis', async (req, res) => {
  try {
    const apis = await API.find({ isApproved: true })
      .populate('owner', 'name')
      .sort({ usageCount: -1 });
    
    res.json(apis);
  } catch (error) {
    console.error('APIs error:', error);
    res.status(500).json({ message: 'Server error fetching APIs' });
  }
});

// Socket.IO for real-time chat
const onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user_online', (userData) => {
    onlineUsers.set(socket.id, {
      socketId: socket.id,
      userId: userData.id,
      name: userData.name,
      avatar: userData.avatar
    });
    
    io.emit('online_users', Array.from(onlineUsers.values()));
  });

  socket.on('join_room', (room) => {
    socket.join(room);
    socket.to(room).emit('user_joined', {
      username: onlineUsers.get(socket.id)?.name || 'Anonymous',
      room
    });
  });

  socket.on('leave_room', (room) => {
    socket.leave(room);
    socket.to(room).emit('user_left', {
      username: onlineUsers.get(socket.id)?.name || 'Anonymous',
      room
    });
  });

  socket.on('send_message', async (data) => {
    try {
      // Save message to database
      const message = new Message({
        room: data.room,
        user: data.user.id,
        message: data.message
      });
      await message.save();

      // Populate user data for the message
      const populatedMessage = await Message.findById(message._id).populate('user', 'name avatar');

      // Broadcast to room
      io.to(data.room).emit('chat_message', {
        user: populatedMessage.user,
        message: populatedMessage.message,
        timestamp: populatedMessage.createdAt
      });
    } catch (error) {
      console.error('Message save error:', error);
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.id);
    io.emit('online_users', Array.from(onlineUsers.values()));
    console.log('User disconnected:', socket.id);
  });
});

// Serve static files
app.use('/uploads', express.static('uploads'));

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`DEVS ARENA server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
