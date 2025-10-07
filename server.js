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
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
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
app.use(express.static('.'));
app.use(passport.initialize());

// MongoDB Connection with better error handling
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB Connected Successfully');
  // Drop the problematic username index if it exists
  return mongoose.connection.collection('users').dropIndex('username_1').catch(() => {
    console.log('ℹ️ No username index to drop or already dropped');
  });
})
.catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
  process.exit(1);
});

// MongoDB Schemas - Fixed to handle the username index issue
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  role: { type: String, enum: ['frontend', 'backend', 'fullstack', 'designer', 'student', 'mentor', 'other'], default: 'other' },
  level: { type: String, enum: ['beginner', 'intermediate', 'pro'], default: 'beginner' },
  skills: [String],
  country: String,
  bio: String,
  avatar: String,
  reputation: { type: Number, default: 0 },
  projectsCount: { type: Number, default: 0 },
  followersCount: { type: Number, default: 0 },
  followingCount: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  githubId: String,
  createdAt: { type: Date, default: Date.now }
}, {
  // Prevent Mongoose from creating indexes automatically
  autoIndex: false
});

// Remove any existing problematic indexes and create only what we need
userSchema.index({ email: 1 }, { unique: true });

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
  name: { type: String, required: true },
  endpoint: { type: String, required: true },
  description: String,
  category: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isApproved: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const lessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: String,
  category: String,
  level: String,
  duration: Number,
  order: Number,
  completedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const hackathonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  startDate: Date,
  endDate: Date,
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  submissions: [{
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    submittedAt: { type: Date, default: Date.now }
  }],
  prizes: [String],
  isActive: { type: Boolean, default: true }
});

const followSchema = new mongoose.Schema({
  follower: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  following: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: String,
  message: String,
  relatedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  relatedProject: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Message = mongoose.model('Message', messageSchema);
const API = mongoose.model('API', apiSchema);
const Lesson = mongoose.model('Lesson', lessonSchema);
const Hackathon = mongoose.model('Hackathon', hackathonSchema);
const Follow = mongoose.model('Follow', followSchema);
const Notification = mongoose.model('Notification', notificationSchema);

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
const openai = process.env.OPENAI_API_KEY ? new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
}) : null;

// Passport GitHub OAuth
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
      
      if (!user) {
        user = await User.findOne({ email: profile.emails?.[0]?.value });
        
        if (!user) {
          user = new User({
            githubId: profile.id,
            name: profile.displayName || profile.username,
            email: profile.emails?.[0]?.value || `${profile.id}@github.com`,
            avatar: profile.photos?.[0]?.value,
            isVerified: true
          });
          await user.save();
        } else {
          user.githubId = profile.id;
          await user.save();
        }
      }
      
      return done(null, user);
    } catch (error) {
      console.error('GitHub OAuth error:', error);
      return done(error, null);
    }
  }));
}

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

const adminAuth = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Routes

// Auth Routes - FIXED REGISTRATION
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('Registration attempt:', req.body);
    const { name, email, password, role, level } = req.body;
    
    // Basic validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'other',
      level: level || 'beginner'
    });

    await user.save();
    console.log('User created successfully:', user.email);

    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        isAdmin: user.isAdmin 
      },
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
        reputation: user.reputation,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    
    res.status(500).json({ message: 'Server error during registration: ' + error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

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
      { 
        userId: user._id, 
        email: user.email,
        isAdmin: user.isAdmin 
      },
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
        reputation: user.reputation,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// GitHub OAuth Routes
app.get('/auth/github', (req, res, next) => {
  if (!process.env.GITHUB_CLIENT_ID) {
    return res.status(501).json({ message: 'GitHub OAuth not configured' });
  }
  passport.authenticate('github', { scope: ['user:email'] })(req, res, next);
});

app.get('/auth/github/callback', 
  (req, res, next) => {
    if (!process.env.GITHUB_CLIENT_ID) {
      return res.redirect('/?auth=not_configured');
    }
    passport.authenticate('github', { failureRedirect: '/?auth=failed' })(req, res, next);
  },
  async (req, res) => {
    try {
      const token = jwt.sign(
        { 
          userId: req.user._id, 
          email: req.user.email,
          isAdmin: req.user.isAdmin 
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify({
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        avatar: req.user.avatar,
        isAdmin: req.user.isAdmin
      }))}`);
    } catch (error) {
      console.error('GitHub callback error:', error);
      res.redirect('/?auth=error');
    }
  }
);

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
      .select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const projectsCount = await Project.countDocuments({ author: req.user.userId });
    const followersCount = await Follow.countDocuments({ following: req.user.userId });
    const followingCount = await Follow.countDocuments({ follower: req.user.userId });

    res.json({
      ...user.toObject(),
      projectsCount,
      followersCount,
      followingCount
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Follow/Unfollow Routes
app.post('/api/user/follow/:userId', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    
    if (req.user.userId === targetUserId) {
      return res.status(400).json({ message: 'Cannot follow yourself' });
    }

    const existingFollow = await Follow.findOne({
      follower: req.user.userId,
      following: targetUserId
    });

    if (existingFollow) {
      await Follow.findByIdAndDelete(existingFollow._id);
      res.json({ message: 'Unfollowed successfully', following: false });
    } else {
      const follow = new Follow({
        follower: req.user.userId,
        following: targetUserId
      });
      await follow.save();

      // Create notification
      const notification = new Notification({
        user: targetUserId,
        type: 'follow',
        message: `${req.user.name} started following you`,
        relatedUser: req.user.userId
      });
      await notification.save();

      res.json({ message: 'Followed successfully', following: true });
    }
  } catch (error) {
    console.error('Follow error:', error);
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
    
    if (!title) {
      return res.status(400).json({ message: 'Project title is required' });
    }

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

    if (!openai) {
      return res.json({ 
        code: '// AI feature is currently unavailable\n// Please check if OpenAI API key is configured\nconsole.log("Hello from DEVS ARENA!");' 
      });
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

// Voice Chat AI Route
app.post('/api/ai/voice-chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;

    if (!openai) {
      return res.json({ response: "AI voice chat is currently unavailable. Please try again later." });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: "You are a helpful coding assistant. Provide clear, concise answers suitable for voice responses."
        },
        {
          role: "user",
          content: message
        }
      ],
      max_tokens: 500
    });

    const response = completion.choices[0].message.content;
    res.json({ response });
  } catch (error) {
    console.error('Voice AI error:', error);
    res.status(500).json({ message: 'Error processing voice chat' });
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

app.post('/api/apis', authenticateToken, async (req, res) => {
  try {
    const { name, endpoint, description, category } = req.body;
    
    if (!name || !endpoint) {
      return res.status(400).json({ message: 'API name and endpoint are required' });
    }

    const api = new API({
      name,
      endpoint,
      description,
      category,
      owner: req.user.userId
    });

    await api.save();
    res.status(201).json(api);
  } catch (error) {
    console.error('Create API error:', error);
    res.status(500).json({ message: 'Server error creating API' });
  }
});

// API Testing Playground
app.post('/api/apis/test', authenticateToken, async (req, res) => {
  try {
    const { endpoint, method, headers, body } = req.body;
    
    if (!endpoint) {
      return res.status(400).json({ message: 'Endpoint is required' });
    }

    // Simple fetch to test the endpoint
    const response = await fetch(endpoint, {
      method: method || 'GET',
      headers: headers || {},
      body: body ? JSON.stringify(body) : undefined
    });

    const data = await response.json();
    res.json({
      status: response.status,
      data: data
    });
  } catch (error) {
    console.error('API test error:', error);
    res.status(500).json({ message: 'Error testing API endpoint' });
  }
});

// Devs School Routes
app.get('/api/lessons', async (req, res) => {
  try {
    const lessons = await Lesson.find().sort({ order: 1 });
    res.json(lessons);
  } catch (error) {
    console.error('Lessons error:', error);
    res.status(500).json({ message: 'Server error fetching lessons' });
  }
});

app.post('/api/lessons/complete/:lessonId', authenticateToken, async (req, res) => {
  try {
    await Lesson.findByIdAndUpdate(req.params.lessonId, {
      $addToSet: { completedBy: req.user.userId }
    });
    
    res.json({ message: 'Lesson marked as completed' });
  } catch (error) {
    console.error('Complete lesson error:', error);
    res.status(500).json({ message: 'Server error completing lesson' });
  }
});

// Hackathon Routes
app.get('/api/hackathons', async (req, res) => {
  try {
    const hackathons = await Hackathon.find({ isActive: true })
      .populate('participants', 'name avatar')
      .sort({ startDate: -1 });
    
    res.json(hackathons);
  } catch (error) {
    console.error('Hackathons error:', error);
    res.status(500).json({ message: 'Server error fetching hackathons' });
  }
});

app.post('/api/hackathons/join/:hackathonId', authenticateToken, async (req, res) => {
  try {
    await Hackathon.findByIdAndUpdate(req.params.hackathonId, {
      $addToSet: { participants: req.user.userId }
    });
    
    res.json({ message: 'Joined hackathon successfully' });
  } catch (error) {
    console.error('Join hackathon error:', error);
    res.status(500).json({ message: 'Server error joining hackathon' });
  }
});

// Notification Routes
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ user: req.user.userId })
      .populate('relatedUser', 'name avatar')
      .populate('relatedProject', 'title')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json(notifications);
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ message: 'Server error fetching notifications' });
  }
});

app.put('/api/notifications/read/:notificationId', authenticateToken, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.notificationId, {
      isRead: true
    });
    
    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ message: 'Server error updating notification' });
  }
});

// Admin Routes
app.get('/api/admin/users', authenticateToken, adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

app.put('/api/admin/users/:userId/verify', authenticateToken, adminAuth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { isVerified: true });
    res.json({ message: 'User verified successfully' });
  } catch (error) {
    console.error('Verify user error:', error);
    res.status(500).json({ message: 'Server error verifying user' });
  }
});

app.get('/api/admin/apis/pending', authenticateToken, adminAuth, async (req, res) => {
  try {
    const apis = await API.find({ isApproved: false }).populate('owner', 'name');
    res.json(apis);
  } catch (error) {
    console.error('Pending APIs error:', error);
    res.status(500).json({ message: 'Server error fetching pending APIs' });
  }
});

app.put('/api/admin/apis/:apiId/approve', authenticateToken, adminAuth, async (req, res) => {
  try {
    await API.findByIdAndUpdate(req.params.apiId, { isApproved: true });
    res.json({ message: 'API approved successfully' });
  } catch (error) {
    console.error('Approve API error:', error);
    res.status(500).json({ message: 'Server error approving API' });
  }
});

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
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
    const user = onlineUsers.get(socket.id);
    socket.to(room).emit('user_joined', {
      username: user?.name || 'Anonymous',
      room
    });
  });

  socket.on('leave_room', (room) => {
    socket.leave(room);
    const user = onlineUsers.get(socket.id);
    socket.to(room).emit('user_left', {
      username: user?.name || 'Anonymous',
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

// Create initial admin user - FIXED
async function createAdminUser() {
  try {
    const adminExists = await User.findOne({ email: 'admin@devsarena.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
      const adminUser = new User({
        name: 'Admin',
        email: 'admin@devsarena.com',
        password: hashedPassword,
        role: 'other',
        level: 'pro',
        isAdmin: true,
        isVerified: true
      });
      await adminUser.save();
      console.log('✅ Admin user created');
    } else {
      console.log('ℹ️ Admin user already exists');
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
    // If it's a duplicate key error, try to fix it
    if (error.code === 11000) {
      try {
        // Drop the problematic index
        await mongoose.connection.collection('users').dropIndex('username_1');
        console.log('✅ Problematic username index dropped');
      } catch (dropError) {
        console.log('ℹ️ Could not drop index, might already be dropped');
      }
    }
  }
}

// Create sample data
async function createSampleData() {
  try {
    const lessonCount = await Lesson.countDocuments();
    if (lessonCount === 0) {
      const lessons = [
        { title: 'HTML Basics', content: 'Learn the fundamentals of HTML...', category: 'frontend', level: 'beginner', duration: 30, order: 1 },
        { title: 'CSS Styling', content: 'Master CSS for beautiful websites...', category: 'frontend', level: 'beginner', duration: 45, order: 2 },
        { title: 'JavaScript Fundamentals', content: 'Learn JavaScript programming...', category: 'frontend', level: 'beginner', duration: 60, order: 3 },
        { title: 'Node.js Introduction', content: 'Server-side JavaScript with Node.js...', category: 'backend', level: 'intermediate', duration: 50, order: 4 },
        { title: 'API Development', content: 'Build RESTful APIs...', category: 'backend', level: 'intermediate', duration: 55, order: 5 }
      ];
      await Lesson.insertMany(lessons);
      console.log('✅ Sample lessons created');
    }

    const apiCount = await API.countDocuments();
    if (apiCount === 0) {
      const sampleAPIs = [
        { name: 'JSONPlaceholder', endpoint: 'https://jsonplaceholder.typicode.com/posts', description: 'Fake API for testing', category: 'development', isApproved: true },
        { name: 'OpenWeatherMap', endpoint: 'https://api.openweathermap.org/data/2.5/weather', description: 'Weather data API', category: 'weather', isApproved: true }
      ];
      await API.insertMany(sampleAPIs);
      console.log('✅ Sample APIs created');
    }
  } catch (error) {
    console.error('Error creating sample data:', error);
  }
}

// Serve static files
app.use('/uploads', express.static('uploads'));

const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
  console.log(`🚀 DEVS ARENA server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Wait a bit for MongoDB to be ready
  setTimeout(async () => {
    await createAdminUser();
    await createSampleData();
  }, 2000);
});
