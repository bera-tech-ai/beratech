require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const { OpenAI } = require('openai');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'devs-place-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

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
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = {
      'text/plain': ['.txt', '.md'],
      'text/html': ['.html', '.htm'],
      'text/css': ['.css'],
      'application/javascript': ['.js'],
      'application/json': ['.json'],
      'application/x-python-code': ['.py'],
      'text/x-java': ['.java'],
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'image/png': ['.png'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/svg+xml': ['.svg'],
      'application/zip': ['.zip'],
      'application/x-tar': ['.tar.gz']
    };
    
    const fileExt = path.extname(file.originalname).toLowerCase();
    const mimeType = file.mimetype;
    
    if (allowedTypes[mimeType] && allowedTypes[mimeType].includes(fileExt)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// OpenAI configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/devsplace', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Simple in-memory storage for demo (replace with MongoDB in production)
const users = new Map();
const projects = [];
const messages = [];

// Routes
// Authentication routes
app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date()
    };
    
    users.set(email, user);
    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, user: { username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.get(email);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, user: { username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.json({ loggedIn: false });
  }
});

// File upload route
app.post('/upload', upload.array('files', 5), (req, res) => {
  try {
    const files = req.files.map(file => ({
      filename: file.filename,
      originalname: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype,
      uploadedAt: new Date()
    }));
    
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Projects routes
app.get('/projects', (req, res) => {
  res.json(projects);
});

app.post('/projects', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const project = {
    id: Date.now().toString(),
    title: req.body.title,
    description: req.body.description,
    code: req.body.code,
    files: req.body.files || [],
    author: req.session.username,
    createdAt: new Date(),
    comments: []
  };
  
  projects.unshift(project);
  res.json({ success: true, project });
});

app.post('/projects/:id/comments', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const project = projects.find(p => p.id === req.params.id);
  if (!project) {
    return res.status(404).json({ error: 'Project not found' });
  }
  
  const comment = {
    id: Date.now().toString(),
    author: req.session.username,
    content: req.body.content,
    createdAt: new Date()
  };
  
  project.comments.push(comment);
  res.json({ success: true, comment });
});

// AI Assistant route
app.post('/devs-ai', async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ error: 'AI service not configured' });
    }
    
    const { question } = req.body;
    
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: "You are a helpful coding assistant. Provide detailed, practical answers with code examples when relevant. Format code blocks properly."
        },
        {
          role: "user",
          content: question
        }
      ],
      max_tokens: 1000
    });
    
    const answer = completion.choices[0].message.content;
    res.json({ success: true, answer });
  } catch (error) {
    console.error('AI Error:', error);
    res.status(500).json({ error: 'AI service error' });
  }
});

// Socket.io for real-time chat
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // Send message history to new user
  socket.emit('messageHistory', messages.slice(-50));
  
  socket.on('sendMessage', (data) => {
    const message = {
      id: Date.now().toString(),
      username: data.username,
      text: data.text,
      file: data.file,
      timestamp: new Date()
    };
    
    messages.push(message);
    
    // Broadcast to all connected clients
    io.emit('newMessage', message);
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Devs Place server running on port ${PORT}`);
  console.log('Make sure to create an "uploads" directory for file storage');
});
