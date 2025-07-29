const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'alpha_tech_secret_key';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/alphatech';
mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
})
.then(() => {
  console.log('Connected to MongoDB successfully');
  
  // Initialize admin count after successful connection
  initializeAdminCount();
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  console.log('Please make sure MongoDB is installed and running on your system');
  console.log('For production, make sure MONGODB_URI environment variable is set');
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ['admin', 'facilitator'] }
});

const User = mongoose.model('User', userSchema);

// Student Schema
const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  class: { type: Number, required: true },
  paid: { type: mongoose.Schema.Types.Mixed, default: false }, // false, 'pending', true
  createdAt: { type: Date, default: Date.now }
});

const Student = mongoose.model('Student', studentSchema);

// Admin Confirmed Count Schema
const countSchema = new mongoose.Schema({
  count: { type: Number, default: 0 }
});

const AdminCount = mongoose.model('AdminCount', countSchema);

// Initialize admin count if not exists
async function initializeAdminCount() {
  try {
    const count = await AdminCount.findOne();
    if (!count) {
      await AdminCount.create({ count: 0 });
      console.log('Admin count initialized');
    }
  } catch (error) {
    console.error('Error initializing admin count:', error);
  }
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// Simple test route
app.get('/', (req, res) => {
  res.json({ message: 'Alpha Tech Management System API' });
});

// Setup route to create initial users
app.get('/setup', async (req, res) => {
  try {
    // Check if users already exist
    const existingUsers = await User.countDocuments();
    if (existingUsers > 0) {
      return res.json({ message: 'Users already exist' });
    }
    
    const adminPassword = await bcrypt.hash('admin777', 10);
    const facilitatorPassword = await bcrypt.hash('facil456', 10);
    
    await User.create([
      { username: 'admin', password: adminPassword, role: 'admin' },
      { username: 'facilitator', password: facilitatorPassword, role: 'facilitator' }
    ]);
    
    res.json({ message: 'Users created successfully! You can now login with admin/admin777 or facilitator/facil456' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, role: user.role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all students
app.get('/api/students', authenticateToken, async (req, res) => {
  try {
    const students = await Student.find().sort({ class: 1, name: 1 });
    res.json(students);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add student
app.post('/api/students', authenticateToken, async (req, res) => {
  try {
    const student = new Student(req.body);
    await student.save();
    res.status(201).json(student);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update student
app.put('/api/students/:id', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(student);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete student (admin only)
app.delete('/api/students/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    await Student.findByIdAndDelete(req.params.id);
    res.json({ message: 'Student deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Toggle payment status
app.put('/api/students/:id/payment', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findById(req.params.id);
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    if (req.user.role === 'facilitator') {
      // Facilitator can only mark as pending if not already confirmed
      if (student.paid !== true) {
        student.paid = 'pending';
      }
    } else if (req.user.role === 'admin') {
      // Admin can toggle between all states
      const adminCount = await AdminCount.findOne();
      
      if (student.paid === 'pending') {
        student.paid = true;
        adminCount.count += 1;
      } else if (student.paid === true) {
        student.paid = false;
        adminCount.count = Math.max(0, adminCount.count - 1);
      } else {
        student.paid = true;
        adminCount.count += 1;
      }
      
      await adminCount.save();
    }
    
    await student.save();
    res.json(student);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get admin confirmed count
app.get('/api/admin-count', authenticateToken, async (req, res) => {
  try {
    const count = await AdminCount.findOne();
    res.json({ count: count ? count.count : 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Alpha Tech Server running on port ${PORT}`);
  console.log('Visit http://localhost:5000/setup to create initial users (for local development)');
});