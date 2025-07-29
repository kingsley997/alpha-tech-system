const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'alpha_tech_secret_key';

// --- Add this near the top to see when the app starts handling requests ---
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] Incoming request: ${req.method} ${req.url}`);
  next();
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/alphatech';
console.log(`[${new Date().toISOString()}] MONGODB_URI loaded from environment:`, !!process.env.MONGODB_URI);
console.log(`[${new Date().toISOString()}] Attempting to connect to MongoDB Atlas...`);

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
})
.then(() => {
  console.log(`[${new Date().toISOString()}] ✅ SUCCESS: Connected to MongoDB Atlas`);
  console.log(`[${new Date().toISOString()}] Calling initializeAdminCount...`);
  initializeAdminCount();
  console.log(`[${new Date().toISOString()}] Returned from initializeAdminCount call.`);
})
.catch(err => {
  console.error(`[${new Date().toISOString()}] ❌ FAILED: MongoDB connection error:`, err);
  console.log(`[${new Date().toISOString()}] Please make sure MongoDB is installed and running on your system`);
  console.log(`[${new Date().toISOString()}] For production, make sure MONGODB_URI environment variable is set`);
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
  console.log(`[${new Date().toISOString()}] -> Inside initializeAdminCount function`);
  try {
    console.log(`[${new Date().toISOString()}] -> About to call AdminCount.findOne()`);
    const count = await AdminCount.findOne();
    console.log(`[${new Date().toISOString()}] -> AdminCount.findOne() returned:`, count !== null ? `Found document with count: ${count.count}` : "No document found");
    if (!count) {
      console.log(`[${new Date().toISOString()}] -> Creating initial AdminCount document...`);
      await AdminCount.create({ count: 0 });
      console.log(`[${new Date().toISOString()}] -> Admin count initialized to 0`);
    } else {
      console.log(`[${new Date().toISOString()}] -> Admin count already exists with value:`, count.count);
    }
  } catch (error) {
    console.error(`[${new Date().toISOString()}] -> ERROR in initializeAdminCount:`, error.message);
    // Optionally log the full error stack if needed for debugging
    console.error(error);
  }
  console.log(`[${new Date().toISOString()}] <- Exiting initializeAdminCount function`);
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
  console.log(`[${new Date().toISOString()}] -> Handling GET / request`);
  res.json({ message: 'Alpha Tech Management System API' });
});

// Setup route to create initial users
app.get('/setup', async (req, res) => {
  console.log(`[${new Date().toISOString()}] -> Handling /setup request`);
  try {
    console.log(`[${new Date().toISOString()}] -> About to call User.countDocuments()`);
    const existingUsers = await User.countDocuments();
    console.log(`[${new Date().toISOString()}] -> User.countDocuments() returned:`, existingUsers);

    if (existingUsers > 0) {
      console.log(`[${new Date().toISOString()}] <- /setup: Users already exist`);
      return res.json({ message: 'Users already exist' });
    }

    console.log(`[${new Date().toISOString()}] -> /setup: Creating initial users...`);
    const adminPassword = await bcrypt.hash('admin777', 10);
    const facilitatorPassword = await bcrypt.hash('facil456', 10);

    await User.create([
      { username: 'admin', password: adminPassword, role: 'admin' },
      { username: 'facilitator', password: facilitatorPassword, role: 'facilitator' }
    ]);

    console.log(`[${new Date().toISOString()}] <- /setup: Users created successfully!`);
    res.json({ message: 'Users created successfully! You can now login with admin/admin777 or facilitator/facil456' });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] -> ERROR in /setup route:`, error.message);
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
  console.log(`[${new Date().toISOString()}] Alpha Tech Server running on port ${PORT}`);
  console.log(`[${new Date().toISOString()}] Visit http://localhost:5000/setup to create initial users (for local development)`);
});