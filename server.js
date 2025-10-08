require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const OpenAI = require('openai');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Security middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000
});
app.use(limiter);

// Session configuration
app.use(session({
  secret: process.env.JWT_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/devsarena')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// OpenAI initialization (optional - won't break if no key)
let openai;
if (process.env.OPENAI_API_KEY) {
  openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
  });
} else {
  console.log('OpenAI API key not provided - AI features disabled');
}

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  country: String,
  skillLevel: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'], default: 'beginner' },
  developerType: { type: String, enum: ['frontend', 'backend', 'full-stack', 'student', 'mobile', 'devops'], default: 'full-stack' },
  bio: String,
  avatar: String,
  banner: String,
  rank: { type: String, default: 'Novice' },
  reputation: { type: Number, default: 0 },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isOnline: { type: Boolean, default: false },
  lastSeen: Date,
  githubId: String,
  isAdmin: { type: Boolean, default: false },
  xp: { type: Number, default: 0 },
  badges: [String],
  isVerified: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  channel: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  type: { type: String, enum: ['text', 'code', 'file'], default: 'text' },
  fileName: String,
  fileUrl: String,
  language: String,
  timestamp: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  name: String,
  description: String,
  techStack: [String],
  githubUrl: String,
  liveUrl: String,
  image: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  collaborators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    timestamp: { type: Date, default: Date.now }
  }],
  views: { type: Number, default: 0 },
  isPublic: { type: Boolean, default: true },
  category: String,
  createdAt: { type: Date, default: Date.now }
});

const apiSchema = new mongoose.Schema({
  name: String,
  description: String,
  endpoint: String,
  method: { type: String, enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], default: 'GET' },
  headers: Object,
  body: Object,
  category: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isApproved: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const lessonSchema = new mongoose.Schema({
  title: String,
  content: String,
  course: String,
  order: Number,
  difficulty: { type: String, enum: ['beginner', 'intermediate', 'advanced'], default: 'beginner' },
  codeExample: String,
  quiz: [{
    question: String,
    options: [String],
    correctAnswer: Number,
    explanation: String
  }]
});

const hackathonSchema = new mongoose.Schema({
  name: String,
  description: String,
  rules: String,
  prize: String,
  startDate: Date,
  endDate: Date,
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  submissions: [{
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    participant: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    score: Number,
    submittedAt: { type: Date, default: Date.now }
  }],
  isActive: { type: Boolean, default: true },
  winner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const toolSchema = new mongoose.Schema({
  name: String,
  description: String,
  category: String,
  input: String,
  output: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  usageCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// MongoDB Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Project = mongoose.model('Project', projectSchema);
const API = mongoose.model('API', apiSchema);
const Lesson = mongoose.model('Lesson', lessonSchema);
const Hackathon = mongoose.model('Hackathon', hackathonSchema);
const Tool = mongoose.model('Tool', toolSchema);

// GitHub OAuth Strategy
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:5000/auth/github/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
      
      if (!user) {
        user = new User({
          githubId: profile.id,
          fullName: profile.displayName || profile.username,
          email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
          avatar: profile.photos?.[0]?.value,
          bio: profile._json.bio || '',
          developerType: 'full-stack',
          isVerified: true
        });
        await user.save();
      }
      
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }));
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (error) {
      return res.status(403).json({ error: 'Invalid token' });
    }
  } else {
    req.user = null;
    next();
  }
};

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Serve static files
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Auth routes
app.post('/api/register', async (req, res) => {
  try {
    console.log('Registration attempt:', req.body);
    
    const { fullName, email, password, country, skillLevel, developerType, bio } = req.body;
    
    // Validate required fields
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'Full name, email, and password are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = new User({
      fullName,
      email,
      password: hashedPassword,
      country: country || '',
      skillLevel: skillLevel || 'beginner',
      developerType: developerType || 'full-stack',
      bio: bio || ''
    });

    await user.save();
    console.log('User created successfully:', user.email);

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'dev-secret');
    
    // Return user data without password
    const userResponse = {
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      country: user.country,
      skillLevel: user.skillLevel,
      developerType: user.developerType,
      bio: user.bio,
      avatar: user.avatar,
      reputation: user.reputation,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt
    };

    res.json({ 
      token, 
      user: userResponse 
    });
  } catch (error) {
    console.error('Registration error:', error);
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
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: 'Account has been suspended' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'dev-secret');
    user.isOnline = true;
    await user.save();

    // Return user data without password
    const userResponse = {
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      country: user.country,
      skillLevel: user.skillLevel,
      developerType: user.developerType,
      bio: user.bio,
      avatar: user.avatar,
      reputation: user.reputation,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt
    };

    res.json({ 
      token, 
      user: userResponse 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GitHub OAuth routes (only if configured)
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

  app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/' }),
    async (req, res) => {
      try {
        const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET || 'dev-secret');
        req.user.isOnline = true;
        await req.user.save();
        
        res.redirect(`/?token=${token}`);
      } catch (error) {
        res.redirect('/?error=auth_failed');
      }
    }
  );
}

// User routes
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ reputation: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    res.json(req.user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .populate('followers', 'fullName avatar')
      .populate('following', 'fullName avatar');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find({ isPublic: true })
      .populate('owner', 'fullName avatar')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json({
      projects,
      total: projects.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const project = new Project({
      ...req.body,
      owner: req.user._id,
      techStack: Array.isArray(req.body.techStack) ? req.body.techStack : 
                (req.body.techStack ? req.body.techStack.split(',').map(t => t.trim()) : [])
    });
    await project.save();
    
    const populatedProject = await Project.findById(project._id)
      .populate('owner', 'fullName avatar');
    
    res.json(populatedProject);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API Hub routes
app.get('/api/apis', async (req, res) => {
  try {
    const apis = await API.find({ isApproved: true });
    res.json(apis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/apis', authenticateToken, async (req, res) => {
  try {
    const api = new API({
      ...req.body,
      owner: req.user._id
    });
    await api.save();
    res.json(api);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// AI Routes (only if OpenAI is configured)
app.post('/api/ai/code', authenticateToken, async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({ error: 'AI features are not configured' });
    }

    const { prompt, language } = req.body;
    
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: `You are an expert ${language} developer. Write clean, efficient, and well-commented code.`
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 1000
    });

    res.json({ code: completion.choices[0].message.content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ai/explain', authenticateToken, async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({ error: 'AI features are not configured' });
    }

    const { code } = req.body;
    
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: "You are a programming instructor. Explain the provided code in simple terms, highlighting key concepts and potential improvements."
        },
        {
          role: "user",
          content: `Explain this code:\n\n${code}`
        }
      ],
      max_tokens: 500
    });

    res.json({ explanation: completion.choices[0].message.content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Learning routes
app.get('/api/lessons', async (req, res) => {
  try {
    const { course } = req.query;
    const query = course ? { course } : {};
    const lessons = await Lesson.find(query).sort({ order: 1 });
    res.json(lessons);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tools routes
app.post('/api/tools/json-format', async (req, res) => {
  try {
    const { json } = req.body;
    const formatted = JSON.stringify(JSON.parse(json), null, 2);
    
    res.json({ formatted });
  } catch (error) {
    res.status(400).json({ error: 'Invalid JSON' });
  }
});

app.post('/api/tools/regex-test', async (req, res) => {
  try {
    const { pattern, text, flags } = req.body;
    const regex = new RegExp(pattern, flags);
    const matches = text.match(regex);
    const testResult = regex.test(text);
    
    res.json({ matches, testResult });
  } catch (error) {
    res.status(400).json({ error: 'Invalid regex pattern' });
  }
});

app.post('/api/tools/base64', async (req, res) => {
  try {
    const { action, text } = req.body;
    let result;
    
    if (action === 'encode') {
      result = Buffer.from(text).toString('base64');
    } else {
      result = Buffer.from(text, 'base64').toString('utf8');
    }
    
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Invalid input' });
  }
});

// Hackathon routes
app.get('/api/hackathons', async (req, res) => {
  try {
    const hackathons = await Hackathon.find()
      .populate('participants', 'fullName avatar')
      .populate('winner', 'fullName avatar')
      .sort({ startDate: -1 });
    res.json(hackathons);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard routes
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const userProjects = await Project.countDocuments({ owner: req.user._id });
    const userAPIs = await API.countDocuments({ owner: req.user._id });
    const userHackathons = await Hackathon.countDocuments({ participants: req.user._id });
    
    const stats = {
      projects: userProjects,
      apis: userAPIs,
      hackathons: userHackathons,
      reputation: req.user.reputation,
      followers: req.user.followers.length,
      following: req.user.following.length
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin routes
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalProjects: await Project.countDocuments(),
      totalAPIs: await API.countDocuments(),
      pendingAPIs: await API.countDocuments({ isApproved: false }),
      onlineUsers: await User.countDocuments({ isOnline: true }),
      totalHackathons: await Hackathon.countDocuments(),
      activeHackathons: await Hackathon.countDocuments({ isActive: true }),
      bannedUsers: await User.countDocuments({ isBanned: true })
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO for real-time features
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-channel', (channel) => {
    socket.join(channel);
  });

  socket.on('send-message', async (data) => {
    try {
      const message = new Message({
        channel: data.channel,
        user: data.userId,
        content: data.content,
        type: data.type
      });
      await message.save();

      const populatedMessage = await Message.findById(message._id)
        .populate('user', 'fullName avatar');

      io.to(data.channel).emit('new-message', populatedMessage);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('user-typing', (data) => {
    socket.to(data.channel).emit('user-typing', {
      user: data.user,
      isTyping: data.isTyping
    });
  });

  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
  });
});

// Initialize sample data
async function initializeSampleData() {
  try {
    // Create admin user if doesn't exist
    const adminExists = await User.findOne({ email: 'admin@devsarena.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 12);
      const adminUser = new User({
        fullName: 'System Admin',
        email: 'admin@devsarena.com',
        password: hashedPassword,
        country: 'US',
        skillLevel: 'expert',
        developerType: 'full-stack',
        bio: 'System Administrator',
        isAdmin: true,
        isVerified: true
      });
      await adminUser.save();
      console.log('Admin user created');
    }

    // Create sample lessons
    const lessonCount = await Lesson.countDocuments();
    if (lessonCount === 0) {
      const sampleLessons = [
        {
          title: 'HTML Basics',
          content: `# HTML Basics\n\nHTML is the standard markup language for creating Web pages.`,
          course: 'html',
          order: 1,
          difficulty: 'beginner',
          codeExample: '<!DOCTYPE html>\n<html>\n<head>\n<title>Page Title</title>\n</head>\n<body>\n<h1>My First Heading</h1>\n<p>My first paragraph.</p>\n</body>\n</html>'
        },
        {
          title: 'CSS Introduction',
          content: `# CSS Introduction\n\nCSS is used to style and layout web pages.`,
          course: 'css',
          order: 1,
          difficulty: 'beginner',
          codeExample: 'body {\\n  background-color: lightblue;\\n}\\n\\nh1 {\\n  color: white;\\n  text-align: center;\\n}'
        }
      ];
      await Lesson.insertMany(sampleLessons);
      console.log('Sample lessons added');
    }

    // Create sample APIs
    const apiCount = await API.countDocuments();
    if (apiCount === 0) {
      const sampleAPIs = [
        {
          name: 'JSONPlaceholder',
          description: 'Fake Online REST API for Testing and Prototyping',
          endpoint: 'https://jsonplaceholder.typicode.com/posts',
          method: 'GET',
          category: 'Testing',
          isApproved: true
        }
      ];
      await API.insertMany(sampleAPIs);
      console.log('Sample APIs added');
    }

  } catch (error) {
    console.log('Error initializing sample data:', error);
  }
}

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
  initializeSampleData();
});
