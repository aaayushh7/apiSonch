require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { GridFsStorage } = require('multer-gridfs-storage');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

// CORS middleware remains the same as your original code
app.use((req, res, next) => {
  const allowedOrigins = ['https://sonch.org.in', 'http://localhost:5173'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, auth-token');
  res.header('Access-Control-Expose-Headers', 'auth-token');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).json({ body: "OK" });
  }
  next();
});

const mongoURI = process.env.MONGO_URI || "mongodb+srv://secondmailtest834:lL7iH3ydKLmAMXoF@cluster0.duf4b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

let gfs;

mongoose.connect(mongoURI)
  .then(() => {
    console.log('Connected to MongoDB');
    gfs = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: 'uploads'
    });
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Use memory storage instead of GridFS storage
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Schema definitions remain the same
const blogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, required: true },
  bannerId: { type: String }, // Changed from imageId to bannerId
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Blog = mongoose.model('Blog', blogSchema);
const Admin = mongoose.model('Admin', adminSchema);

// Authentication middleware remains the same
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

// Fixed file upload route

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const filename = crypto.randomBytes(16).toString('hex') + path.extname(req.file.originalname);
  
  const uploadStream = gfs.openUploadStream(filename, {
    metadata: { originalname: req.file.originalname }
  });

  // Write buffer to GridFS and handle the promise
  uploadStream.write(req.file.buffer);
  uploadStream.end();

  // Get the file id from the upload stream
  const fileId = uploadStream.id;

  // Return after the upload is complete
  uploadStream.on('finish', () => {
    return res.json({ 
      fileId: fileId,
      filename: filename 
    });
  });

  uploadStream.on('error', (error) => {
    console.error('Upload error:', error);
    return res.status(500).json({ message: 'Error uploading file' });
  });
});

app.get('/api/images/:fileId', (req, res) => {
  try {
    const downloadStream = gfs.openDownloadStream(new mongoose.Types.ObjectId(req.params.fileId));
    downloadStream.on('error', () => {
      return res.status(404).json({ message: 'Image not found' });
    });
    res.set('Content-Type', 'application/octet-stream');
    downloadStream.pipe(res);
  } catch (err) {
    res.status(500).json({ message: 'Error retrieving image' });
  }
});

// Existing routes remain the same
app.get('/', (req, res) => {
  res.status(200).json({ message: 'API is running' });
});

// Auth Routes (remain the same)
app.post('/api/auth/setup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const adminExists = await Admin.findOne({ email });
    if (adminExists) {
      return res.status(400).json({ message: 'Admin already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: 'Invalid email or password' });

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ _id: admin._id, email: admin.email }, process.env.JWT_SECRET);
    res.header('auth-token', token).json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Updated Blog Routes to handle images
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

// Create blog
app.post('/api/blogs', authenticateToken, async (req, res) => {
  try {
    const blog = new Blog({
      title: req.body.title,
      content: req.body.content,
      author: req.admin.email,
      bannerId: req.body.bannerId
    });
    const newBlog = await blog.save();
    res.status(201).json(newBlog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update blog
app.put('/api/blogs/:id', authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });
    
    if (blog.author !== req.admin.email) {
      return res.status(403).json({ message: 'Not authorized to update this blog' });
    }

    // If there's a new banner and old one exists, delete old one
    if (blog.bannerId && req.body.bannerId && blog.bannerId !== req.body.bannerId) {
      await gfs.delete(new mongoose.Types.ObjectId(blog.bannerId));
    }

    blog.title = req.body.title;
    blog.content = req.body.content;
    blog.bannerId = req.body.bannerId;
    blog.updatedAt = Date.now();

    const updatedBlog = await blog.save();
    res.json(updatedBlog);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete blog
app.delete('/api/blogs/:id', authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });
    
    if (blog.author !== req.admin.email) {
      return res.status(403).json({ message: 'Not authorized to delete this blog' });
    }

    if (blog.bannerId) {
      await gfs.delete(new mongoose.Types.ObjectId(blog.bannerId));
    }

    await blog.deleteOne();
    res.json({ message: 'Blog deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Error handling middleware (remains the same)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});

// Timeout handler (remains the same)
app.use((req, res, next) => {
  res.setTimeout(30000, () => {
    res.status(504).json({ message: 'Request timeout' });
  });
  next();
});

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));