require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { GridFsStorage } = require('multer-gridfs-storage');
const sharp = require('sharp');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

// CORS middleware remains the same as your original code
const allowedOrigins = ['https://sonch.org.in', 'http://localhost:5173'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  exposedHeaders: ['auth-token'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'auth-token']
}));

mongoose.connect(process.env.MONGO_URI || "mongodb+srv://secondmailtest834:lL7iH3ydKLmAMXoF@cluster0.duf4b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0");

let gfs;

mongoose.connection.once('open', () => {
  console.log("Connected to MongoDB successfully.");
  gfs = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
});


// mongoose.connect(mongoURI)
//   .then(() => {
//     console.log('Connected to MongoDB');
//     gfs = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
//       bucketName: 'uploads'
//     });
//   })
//   .catch(err => console.error('MongoDB connection error:', err));

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // Increased limit for base64 encoded images
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    
    // Handle both regular uploads and base64 content
    if (req.body.base64) {
      cb(null, true);
      return;
    }
    
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error('Invalid file type'));
      return;
    }
    cb(null, true);
  }
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
const verifyToken = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || req.header('auth-token');
    if (!token) return res.status(401).json({ message: 'Access denied' });

    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

const authenticateToken = verifyToken;

const processImage = async (imageBuffer, options = {}) => {
  const {
    maxWidth = 1200,
    maxHeight = 800,
    quality = 80,
    format = 'jpeg'
  } = options;

  return sharp(imageBuffer)
    .resize(maxWidth, maxHeight, {
      fit: 'inside',
      withoutEnlargement: true
    })
    [format]({ quality })
    .toBuffer();
};

// Fixed file upload route

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    let imageBuffer;
    
    // Handle base64 uploads (from Quill editor)
    if (req.body.base64) {
      const base64Data = req.body.base64.split(';base64,').pop();
      imageBuffer = Buffer.from(base64Data, 'base64');
    } 
    // Handle multipart uploads (from banner upload)
    else if (req.file) {
      imageBuffer = req.file.buffer;
    } else {
      return res.status(400).json({ message: 'No image data provided' });
    }

    // Process the image
    const optimizedBuffer = await processImage(imageBuffer, {
      maxWidth: 1200,
      maxHeight: 800,
      quality: 80,
      format: 'jpeg'
    });

    // Generate unique filename
    const filename = `${crypto.randomBytes(16).toString('hex')}.jpg`;
    
    // Upload to GridFS
    const uploadStream = gfs.openUploadStream(filename, {
      metadata: {
        originalname: req.file ? req.file.originalname : 'content-image.jpg',
        contentType: 'image/jpeg'
      }
    });

    // Handle upload errors
    uploadStream.on('error', (error) => {
      console.error('GridFS upload error:', error);
      res.status(500).json({ message: 'Error saving image' });
    });

    // Return success response when upload completes
    uploadStream.on('finish', () => {
      res.json({
        fileId: uploadStream.id.toString(),
        url: `/api/images/${uploadStream.id.toString()}`
      });
    });

    // Write the optimized buffer to GridFS
    uploadStream.end(optimizedBuffer);

  } catch (error) {
    console.error('Image processing error:', error);
    res.status(500).json({ 
      message: 'Error processing image',
      error: error.message 
    });
  }
});

app.get('/api/images/:fileId', async (req, res) => {
  try {
    const downloadStream = gfs.openDownloadStream(new mongoose.Types.ObjectId(req.params.fileId));
    
    res.set({
      'Cache-Control': 'public, max-age=31536000',
      'Content-Type': 'image/jpeg'
    });

    downloadStream.on('error', () => {
      res.status(404).json({ message: 'Image not found' });
    });

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

app.post('/api/auth/logout', verifyToken, async (req, res) => {
  try {
    // Get the token from the header
    const token = req.header('auth-token');

    // Optional: Add token to a blacklist in your database
    // await BlacklistedToken.create({ token });
    
    // Clear the auth token from the response header
    res.removeHeader('auth-token');
    
    res.status(200).json({ message: 'Logged out successfully' });
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

app.delete('/api/blogs/:id', authenticateToken, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: 'Blog not found' });

    // Make author check case-insensitive
    if (blog.author.toLowerCase() !== req.admin.email.toLowerCase()) {
      console.log('Author mismatch:', { blogAuthor: blog.author, userEmail: req.admin.email });
      return res.status(403).json({ message: 'Not authorized to delete this blog' });
    }

    if (blog.bannerId) {
      try {
        await gfs.delete(new mongoose.Types.ObjectId(blog.bannerId));
      } catch (error) {
        console.error('Error deleting banner:', error);
      }
    }

    await blog.deleteOne();
    res.json({ message: 'Blog deleted' });
  } catch (err) {
    console.error('Delete error:', err);
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