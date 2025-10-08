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
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// OpenAI initialization
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  country: String,
  skillLevel: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'] },
  developerType: { type: String, enum: ['frontend', 'backend', 'full-stack', 'student', 'mobile', 'devops'] },
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
  method: { type: String, enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
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
  difficulty: { type: String, enum: ['beginner', 'intermediate', 'advanced'] },
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
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
    const { fullName, email, password, country, skillLevel, developerType, bio } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      fullName,
      email,
      password: hashedPassword,
      country,
      skillLevel,
      developerType,
      bio
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ 
      token, 
      user: { 
        ...user._doc, 
        password: undefined 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: 'Account has been suspended' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    user.isOnline = true;
    await user.save();

    res.json({ 
      token, 
      user: { 
        ...user._doc, 
        password: undefined 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GitHub OAuth routes
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET);
      req.user.isOnline = true;
      await req.user.save();
      
      res.redirect(`/?token=${token}`);
    } catch (error) {
      res.redirect('/?error=auth_failed');
    }
  }
);

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

app.put('/api/users/:id', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const updates = { ...req.body };
    if (req.file) {
      updates.avatar = `/uploads/${req.file.filename}`;
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    ).select('-password');

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const userToFollow = await User.findById(req.params.id);
    const currentUser = await User.findById(req.user._id);

    if (!userToFollow.followers.includes(req.user._id)) {
      userToFollow.followers.push(req.user._id);
      currentUser.following.push(userToFollow._id);
      
      await userToFollow.save();
      await currentUser.save();
    }

    res.json({ message: 'Followed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Chat routes
app.get('/api/messages/:channel', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({ channel: req.params.channel })
      .populate('user', 'fullName avatar')
      .sort({ timestamp: 1 })
      .limit(100);
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project routes
app.get('/api/projects', async (req, res) => {
  try {
    const { page = 1, limit = 10, category } = req.query;
    const query = category ? { category, isPublic: true } : { isPublic: true };
    
    const projects = await Project.find(query)
      .populate('owner', 'fullName avatar')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Project.countDocuments(query);
    
    res.json({
      projects,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/projects/user/:userId', authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find({ owner: req.params.userId })
      .populate('owner', 'fullName avatar')
      .sort({ createdAt: -1 });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const project = new Project({
      ...req.body,
      owner: req.user._id,
      techStack: JSON.parse(req.body.techStack || '[]'),
      image: req.file ? `/uploads/${req.file.filename}` : null
    });
    await project.save();
    
    const populatedProject = await Project.findById(project._id)
      .populate('owner', 'fullName avatar');
    
    res.json(populatedProject);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects/:id/like', authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project.likes.includes(req.user._id)) {
      project.likes.push(req.user._id);
      await project.save();
      
      // Add reputation to project owner
      await User.findByIdAndUpdate(project.owner, {
        $inc: { reputation: 5 }
      });
    }
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects/:id/comment', authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    project.comments.push({
      user: req.user._id,
      content: req.body.content
    });
    await project.save();
    
    const populatedProject = await Project.findById(project._id)
      .populate('owner', 'fullName avatar')
      .populate('comments.user', 'fullName avatar');
    
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

app.post('/api/apis/test', authenticateToken, async (req, res) => {
  try {
    const { url, method, headers, body } = req.body;
    
    const response = await fetch(url, {
      method,
      headers: headers || {},
      body: method !== 'GET' ? JSON.stringify(body) : undefined
    });

    const data = await response.json();
    
    // Update usage count
    await API.findOneAndUpdate(
      { endpoint: url },
      { $inc: { usageCount: 1 } }
    );
    
    res.json({
      status: response.status,
      headers: Object.fromEntries(response.headers),
      data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// AI Routes
app.post('/api/ai/code', authenticateToken, async (req, res) => {
  try {
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

app.post('/api/ai/review', authenticateToken, async (req, res) => {
  try {
    const { code, language } = req.body;
    
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: `You are a senior ${language} developer reviewing code. Provide constructive feedback on code quality, best practices, performance, and security.`
        },
        {
          role: "user",
          content: `Review this ${language} code:\n\n${code}`
        }
      ],
      max_tokens: 800
    });

    res.json({ review: completion.choices[0].message.content });
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

app.get('/api/lessons/:id', async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id);
    res.json(lesson);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tools routes
app.get('/api/tools', async (req, res) => {
  try {
    const tools = await Tool.find().sort({ usageCount: -1 });
    res.json(tools);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tools/json-format', async (req, res) => {
  try {
    const { json } = req.body;
    const formatted = JSON.stringify(JSON.parse(json), null, 2);
    
    // Log tool usage
    await Tool.findOneAndUpdate(
      { name: 'JSON Formatter' },
      { $inc: { usageCount: 1 } },
      { upsert: true }
    );
    
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
    
    // Log tool usage
    await Tool.findOneAndUpdate(
      { name: 'Regex Tester' },
      { $inc: { usageCount: 1 } },
      { upsert: true }
    );
    
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
    
    // Log tool usage
    await Tool.findOneAndUpdate(
      { name: 'Base64 Encoder/Decoder' },
      { $inc: { usageCount: 1 } },
      { upsert: true }
    );
    
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

app.post('/api/hackathons', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const hackathon = new Hackathon(req.body);
    await hackathon.save();
    res.json(hackathon);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/hackathons/:id/join', authenticateToken, async (req, res) => {
  try {
    const hackathon = await Hackathon.findById(req.params.id);
    if (!hackathon.participants.includes(req.user._id)) {
      hackathon.participants.push(req.user._id);
      await hackathon.save();
    }
    res.json(hackathon);
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

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { isBanned, isAdmin, isVerified } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isBanned, isAdmin, isVerified },
      { new: true }
    ).select('-password');
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/apis', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const apis = await API.find().populate('owner', 'fullName email').sort({ createdAt: -1 });
    res.json(apis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/apis/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const api = await API.findByIdAndUpdate(
      req.params.id,
      { isApproved: true },
      { new: true }
    );
    res.json(api);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/apis/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await API.findByIdAndDelete(req.params.id);
    res.json({ message: 'API deleted successfully' });
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
        type: data.type,
        fileName: data.fileName,
        fileUrl: data.fileUrl,
        language: data.language
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
    // Create admin user
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
          content: `# HTML Basics

HTML (HyperText Markup Language) is the standard markup language for creating web pages. It describes the structure of a web page.

## Basic HTML Structure

Every HTML document has a basic structure:

\`\`\`html
<!DOCTYPE html>
<html>
<head>
    <title>Page Title</title>
</head>
<body>
    <h1>My First Heading</h1>
    <p>My first paragraph.</p>
</body>
</html>
\`\`\`

## Key Elements

- **<!DOCTYPE html>**: Defines the document type
- **<html>**: The root element
- **<head>**: Contains meta information
- **<title>**: Sets the page title
- **<body>**: Contains the visible content
- **<h1> to <h6>**: Heading tags
- **<p>**: Paragraph tag

## Try It Yourself

Edit the code in the editor to create your own HTML page!`,
          course: 'html',
          order: 1,
          difficulty: 'beginner',
          codeExample: '<!DOCTYPE html>\n<html>\n<head>\n    <title>My Page</title>\n</head>\n<body>\n    <h1>Welcome to My Website</h1>\n    <p>This is my first web page!</p>\n</body>\n</html>',
          quiz: [
            {
              question: 'What does HTML stand for?',
              options: [
                'Hyper Text Markup Language',
                'High Tech Modern Language',
                'Hyper Transfer Markup Language',
                'Home Tool Markup Language'
              ],
              correctAnswer: 0,
              explanation: 'HTML stands for Hyper Text Markup Language, which is the standard markup language for creating web pages.'
            }
          ]
        },
        {
          title: 'CSS Introduction',
          content: `# CSS Introduction

CSS (Cascading Style Sheets) is used to style and layout web pages.

## Basic CSS Syntax

\`\`\`css
selector {
    property: value;
}
\`\`\`

## Example

\`\`\`css
body {
    background-color: lightblue;
}

h1 {
    color: white;
    text-align: center;
}
\`\`\``,
          course: 'css',
          order: 1,
          difficulty: 'beginner',
          codeExample: '<!DOCTYPE html>\n<html>\n<head>\n    <style>\n        body {\n            background-color: lightblue;\n        }\n        h1 {\n            color: white;\n            text-align: center;\n        }\n    </style>\n</head>\n<body>\n    <h1>Styled Heading</h1>\n    <p>This page has a light blue background.</p>\n</body>\n</html>',
          quiz: [
            {
              question: 'What does CSS stand for?',
              options: [
                'Cascading Style Sheets',
                'Computer Style Sheets',
                'Creative Style System',
                'Colorful Style Sheets'
              ],
              correctAnswer: 0,
              explanation: 'CSS stands for Cascading Style Sheets, which is used for describing the presentation of web pages.'
            }
          ]
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
        },
        {
          name: 'OpenWeatherMap',
          description: 'Weather Data and API',
          endpoint: 'https://api.openweathermap.org/data/2.5/weather',
          method: 'GET',
          category: 'Weather',
          isApproved: true
        }
      ];
      await API.insertMany(sampleAPIs);
      console.log('Sample APIs added');
    }

    // Create sample hackathon
    const hackathonCount = await Hackathon.countDocuments();
    if (hackathonCount === 0) {
      const sampleHackathon = new Hackathon({
        name: 'DEVS ARENA Launch Hackathon',
        description: 'Celebrate the launch of DEVS ARENA with this exciting coding challenge!',
        rules: 'Build any web application using modern technologies. Be creative and innovative!',
        prize: '$1000 cash prize + Featured on DEVS ARENA homepage',
        startDate: new Date(),
        endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        isActive: true
      });
      await sampleHackathon.save();
      console.log('Sample hackathon added');
    }

  } catch (error) {
    console.log('Error initializing sample data:', error);
  }
}

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  initializeSampleData();
});
