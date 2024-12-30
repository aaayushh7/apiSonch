require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'https://sonch.org.in', 'http://localhost:5173');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, auth-token');
    res.header('Access-Control-Expose-Headers', 'auth-token');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
      return res.status(200).json({
        body: "OK"
      });
    }
    
    next();
  });
  
  app.use(express.json());

  mongoose.connect("mongodb+srv://secondmailtest834:lL7iH3ydKLmAMXoF@cluster0.duf4b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));
  
  // Error handling for MongoDB connection
  mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
  });
  
  mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected. Attempting to reconnect...');
  });
  
  mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
  });

// Blog Schema
const blogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Blog = mongoose.model('Blog', blogSchema);  // Fixed this line

// Admin Schema for authentication
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', adminSchema);

app.get('/', (req, res) => {
    res.status(200).json({ message: 'API is running' });
  });

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Initial Admin Setup Route
app.post('/api/auth/setup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if admin already exists
    const adminExists = await Admin.findOne({ email });
    if (adminExists) {
      return res.status(400).json({ message: 'Admin already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new admin
    const admin = new Admin({
      email,
      password: hashedPassword
    });

    await admin.save();
    res.status(201).json({ message: 'Admin created successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin by email
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: 'Invalid email or password' });

    // Validate password
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid email or password' });

    // Create and assign token
    const token = jwt.sign({ _id: admin._id, email: admin.email }, process.env.JWT_SECRET);
    res.header('auth-token', token).json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Blog Routes
// Get all blogs
app.get('/api/blogs', async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ createdAt: -1 });
    res.json(blogs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get single blog
app.get('/api/blogs/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create blog (protected route)
app.post('/api/blogs', authenticateToken, async (req, res) => {
  try {
    const blog = new Blog({
      title: req.body.title,
      content: req.body.content,
      author: req.admin.email
    });
    const newBlog = await blog.save();
    res.status(201).json(newBlog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update blog (protected route)
app.put('/api/blogs/:id', authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });
    
    if (blog.author !== req.admin.email) {
      return res.status(403).json({ message: 'Not authorized to update this blog' });
    }

    blog.title = req.body.title;
    blog.content = req.body.content;
    blog.updatedAt = Date.now();

    const updatedBlog = await blog.save();
    res.json(updatedBlog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete blog (protected route)
app.delete('/api/blogs/:id', authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });
    
    if (blog.author !== req.admin.email) {
      return res.status(403).json({ message: 'Not authorized to delete this blog' });
    }

    await blog.deleteOne();  // Changed from remove() to deleteOne()
    res.json({ message: 'Blog deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something broke!' });
  });
  
  // Add a timeout handler
  app.use((req, res, next) => {
    res.setTimeout(30000, () => {
      res.status(504).json({ message: 'Request timeout' });
    });
    next();
  });
  
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));