require('dotenv').config();
// ADD THESE LINES FOR THE TEST
console.log("--- DOTENV TEST ---");
console.log("MONGO_URI Variable:", process.env.MONGO_URI);
console.log("JWT_SECRET Variable:", process.env.JWT_SECRET);
console.log("---------------------");

const express = require("express");
const path = require('path');
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { authenticateToken } = require("./middleware");
const Event = require('./models/eventModel');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/kmit-club";
app.use(bodyParser.json());
app.use(cors());

// Serve the frontend files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// MongoDB connection
mongoose.connect(MONGO_URI)
.then(() => console.log("✅ MongoDB connected"))
.catch(err => console.error("❌ MongoDB connection error:", err));

// Health endpoint
app.get('/', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
  // optional: process.exit(1);
});

// Validation functions
const validateStudentRollNo = (rollNo) => {
  const pattern = /^(22|23|24|25)BD1A05[A-G][0-9]$/;
  return pattern.test(rollNo);
};
const validateFacultyEmail = (email) => {
  const pattern = /^[A-Za-z]{5,15}[0-9]{0,3}@gmail\.com$/;
  return pattern.test(email);
};
const validateFacultyName = (name) => {
  const pattern = /^[A-Za-z]{1,20}$/;
  return pattern.test(name);
};
const validateFacultyPassword = (password) => {
  const pattern = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*]).{10,}$/;
  return pattern.test(password);
};
const validateClubPassword = (password) => {
  const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/;
  return pattern.test(password);
};
const validateClubHeadUsername = (username) => {
  const pattern = /^[A-Za-z]+-Head$/i;
  return pattern.test(username);
};
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Schemas
const studentSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    name: String,
    rollNumber: String,
    joinedClubs: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Club' }],
    pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Club' }]
});
const Student = mongoose.model("Student", studentSchema);

const facultySchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    name: String,
    email: String
});
const Faculty = mongoose.model("Faculty", facultySchema);

const clubHeadSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    name: String,
    club: { type: mongoose.Schema.Types.ObjectId, ref: 'Club' }
});
const ClubHead = mongoose.model("ClubHead", clubHeadSchema);

const adminSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    name: String
});
const Admin = mongoose.model("Admin", adminSchema);

const clubSchema = new mongoose.Schema({
    name: String,
    slug: { type: String, unique: true, required: true },
    headUsername: { type: String, unique: true, sparse: true }, // sparse allows null
    password: String,
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
    pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
    description: String,
    image: String
});
const Club = mongoose.model("Club", clubSchema);

// REGISTER endpoint (plain text password)
app.post("/register", async (req, res) => {
  try {
    const { role } = req.body;

    if (role === "student") {
      const { studentUsername, studentPassword } = req.body;
      if (!validateStudentRollNo(studentUsername)) {
        return res.status(400).json({ error: "❌ Invalid Roll No format. Use format like: 23BD1A05C7" });
      }
      if (studentPassword !== studentUsername) {
        return res.status(400).json({ error: "❌ Password must match Roll No" });
      }
      const existingStudent = await Student.findOne({ username: studentUsername });
      if (existingStudent) {
        return res.status(400).json({ error: "❌ Student already exists" });
      }
      const student = new Student({
        username: studentUsername,
        password: studentPassword, // PLAIN TEXT
        name: studentUsername,
        rollNumber: studentUsername
      });
      await student.save();
      return res.json({ message: "✅ Student registration successful" });
    }

    if (role === "faculty") {
      const { facultyEmail, facultyPassword, name } = req.body;
      if (!validateFacultyEmail(facultyEmail)) {
        return res.status(400).json({ error: "❌ Invalid email format. Use: 5-15 letters + optional digits + @gmail.com" });
      }
      if (!validateFacultyName(name)) {
        return res.status(400).json({ error: "❌ Invalid name format. Only letters (1-20 characters)" });
      }
      if (!validateFacultyPassword(facultyPassword)) {
        return res.status(400).json({ error: "❌ Invalid password format. Must contain uppercase, lowercase, number, and special character" });
      }
      const existingFaculty = await Faculty.findOne({ username: facultyEmail });
      if (existingFaculty) {
        return res.status(400).json({ error: "❌ Faculty already exists" });
      }
      const faculty = new Faculty({
        username: facultyEmail,
        password: facultyPassword, // PLAIN TEXT
        name,
        email: facultyEmail
      });
      await faculty.save();
      return res.json({ message: "✅ Faculty registration successful" });
    }

    if (role === "clubhead") {
      const { clubUsername, clubPassword } = req.body;
      if (!validateClubHeadUsername(clubUsername)) {
        return res.status(400).json({ error: "❌ Invalid club username format. Use: Clubname-Head" });
      }
      if (!validateClubPassword(clubPassword)) {
        return res.status(400).json({ error: "❌ Invalid password format." });
      }
      const club = await Club.findOne({ headUsername: { $regex: new RegExp(`^${escapeRegex(clubUsername)}$`, 'i') } });
      if (!club) {
        return res.status(400).json({ error: "❌ This club is not configured for a head or the username is incorrect." });
      }
      const existingHead = await ClubHead.findOne({ username: { $regex: new RegExp(`^${escapeRegex(clubUsername)}$`, 'i') } });
      if (existingHead) {
        return res.status(400).json({ error: "❌ This club already has a head assigned." });
      }
      const clubHead = new ClubHead({
        username: clubUsername,
        password: clubPassword, // PLAIN TEXT
        name: clubUsername.replace(/-head$/i, '') + " Head",
        club: club._id
      });
      await clubHead.save();
      return res.json({ message: "✅ Club Head registration successful" });
    }

    if (role === "admin") {
      const { adminId, adminPassword } = req.body;
      if (!/^[a-zA-Z0-9]{4,20}$/.test(adminId)) {
        return res.status(400).json({ error: "❌ Invalid Admin ID format. Use 4-20 alphanumeric characters" });
      }
      if (!validateClubPassword(adminPassword)) {
        return res.status(400).json({ error: "❌ Invalid password format. Must contain uppercase, lowercase, number, and special character" });
      }
      const existingAdmin = await Admin.findOne({ username: adminId });
      if (existingAdmin) {
        return res.status(400).json({ error: "❌ Admin already exists" });
      }
      const admin = new Admin({
        username: adminId,
        password: adminPassword, // PLAIN TEXT
        name: "Admin " + adminId
      });
      await admin.save();
      return res.json({ message: "✅ Admin registration successful" });
    }

    res.status(400).json({ error: "❌ Invalid role" });
  } catch (err) {
    console.error("Registration error:", err);

    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ error: `❌ ${field} already exists` });
    }
    res.status(500).json({ error: "❌ Server error during registration" });
  }
});

// LOGIN endpoint (plain text password compare)
app.post("/login", async (req, res) => {
  try {
    let { role, username, password } = req.body || {};
    username = (username || '').trim();
    console.log('DEBUG /login payload (raw):', { role, usernameProvided: username });
    let user, userModel;
    if (role === "student") userModel = Student;
    else if (role === "faculty") userModel = Faculty;
    else if (role === "clubhead") userModel = ClubHead;
    else if (role === "admin") {
  // Fixed admin credentials for login
  if (username === "admin" && password === "Admin123$") {
    const token = jwt.sign(
      { id: "admin-fixed", role: "admin", username: "admin", name: "Admin User" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    return res.json({ token, role: "admin" });
  } else {
    return res.status(401).json({ error: "Invalid admin credentials" });
  }
}

      

    if (role === 'clubhead') {
      const normalized = username.replace(/(-head)+$/i, '-head');
      const withoutSuffix = normalized.replace(/-head$/i, '');
      user = await userModel.findOne({ $or: [
        { username: { $regex: `^${escapeRegex(normalized)}$`, $options: 'i' } },
        { username: { $regex: `^${escapeRegex(withoutSuffix)}$`, $options: 'i' } },
        { username: { $regex: `^${escapeRegex(withoutSuffix)}-head$`, $options: 'i' } }
      ] });
    } else {
      user = await userModel.findOne({ username: { $regex: `^${escapeRegex(username)}$`, $options: 'i' } });
    }
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    // Compare plain passwords
    if (password !== user.password) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, role, username: user.username, name: user.name }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// All remaining routes as in your code -- DO NOT change logic for dashboards, club join, events etc.

app.get("/student/dashboard", authenticateToken, async (req, res) => {
    if (req.user.role !== "student") return res.status(403).json({ error: "Unauthorized" });
    const student = await Student.findOne({ username: req.user.username })
        .populate('joinedClubs')
        .populate('pendingRequests');
    if (!student) return res.status(404).json({ error: "Student not found" });
    res.json(student);
});
app.get("/clubs", async (req, res) => {
    try {
        const clubs = await Club.find({}, 'name description image slug _id');
        res.json(clubs);
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// DEV: debug endpoint
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug/clubheads', async (req, res) => {
    try {
      const heads = await ClubHead.find({}).populate('club', 'name');
      const out = heads.map(h => ({ id: h._id, username: h.username, clubId: h.club?._id, clubName: h.club?.name || null }));
      res.json(out);
    } catch (err) {
      console.error('Error in /debug/clubheads', err);
      res.status(500).json({ error: 'Server error' });
    }
  });
}

// 1. STUDENT: REQUEST TO JOIN A CLUB
app.post("/student/join-club", authenticateToken, async (req, res) => {
    if (req.user.role !== "student") return res.status(403).json({ error: "Unauthorized" });
    try {
        const { clubId } = req.body;
        const studentId = req.user.id; // From the JWT
        await Club.findByIdAndUpdate(clubId, { $addToSet: { pendingRequests: studentId } });
        await Student.findByIdAndUpdate(studentId, { $addToSet: { pendingRequests: clubId } });
        res.json({ message: "Request sent successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// 2. CLUB HEAD: GET DASHBOARD DATA (INCL. REQUESTS AND MEMBERS)
app.get("/clubhead/dashboard", authenticateToken, async (req, res) => {
    if (req.user.role !== "clubhead") return res.status(403).json({ error: "Unauthorized" });
    try {
        const clubHead = await ClubHead.findById(req.user.id);
         console.log("DEBUG: Checking Club Head:", clubHead); 
        if (!clubHead) return res.status(404).json({ error: "Club head not found" });
        const clubData = await Club.findById(clubHead.club)
            .populate('pendingRequests', 'name username rollNumber')
            .populate('members', 'name username rollNumber');
        if (!clubData) return res.status(404).json({ error: "Club data not found" });
        res.json(clubData);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// 3. CLUB HEAD: RESPOND TO A JOIN REQUEST (ACCEPT/REJECT)
app.post("/clubhead/respond", authenticateToken, async (req, res) => {
    if (req.user.role !== "clubhead") return res.status(403).json({ error: "Unauthorized" });
    try {
        const { studentId, action } = req.body;
        const clubHead = await ClubHead.findById(req.user.id);
        const clubId = clubHead.club;
        await Club.findByIdAndUpdate(clubId, { $pull: { pendingRequests: studentId } });
        await Student.findByIdAndUpdate(studentId, { $pull: { pendingRequests: clubId } });
        if (action === "accept") {
            await Club.findByIdAndUpdate(clubId, { $addToSet: { members: studentId } });
            await Student.findByIdAndUpdate(studentId, { $addToSet: { joinedClubs: clubId } });
        }
        res.json({ message: `Request has been ${action}ed.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

// --- EVENT PROPOSAL & APPROVAL APIS ---

app.post("/clubhead/events", authenticateToken, async (req, res) => {
    if (req.user.role !== "clubhead") {
        return res.status(403).json({ error: "Unauthorized" });
    }
    try {
        const { title, description, date } = req.body;
        const clubHead = await ClubHead.findById(req.user.id);
        if (!clubHead || !clubHead.club) {
            return res.status(404).json({ error: "Could not find the club for this user." });
        }
        const newEvent = new Event({
            title,
            description,
            date,
            club: clubHead.club, 
            status: 'pending'
        });
        await newEvent.save();
        res.status(201).json({ message: "Event proposal submitted successfully!" });
    } catch (err) {
        console.error("Error creating event:", err); 
        res.status(500).json({ error: "Server error while creating event." });
    }
});

app.get("/clubhead/my-events", authenticateToken, async (req, res) => {
    if (req.user.role !== "clubhead") return res.status(403).json({ error: "Unauthorized" });
    try {
        const clubHead = await ClubHead.findById(req.user.id);
        const events = await Event.find({ club: clubHead.club });
        res.json(events);
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/faculty/dashboard", authenticateToken, async (req, res) => {
    if (req.user.role !== "faculty") return res.status(403).json({ error: "Unauthorized" });
    try {
        const pendingEvents = await Event.find({ status: 'pending' }).populate('club', 'name');
        const clubs = await Club.find({}).populate({
            path: 'members',
            select: 'username'
        });
        const students = await Student.find({}, 'username');
        const clubHeads = await ClubHead.find({}, 'username');
        const allUsers = [
            ...students.map(s => ({ username: s.username, role: 'Student' })),
            ...clubHeads.map(ch => ({ username: ch.username, role: 'Club Head' }))
        ];
        res.json({ pendingEvents, clubs, allUsers });
    } catch (err) {
        console.error("Error in /faculty/dashboard:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/faculty/events/respond", authenticateToken, async (req, res) => {
    if (req.user.role !== "faculty") return res.status(403).json({ error: "Unauthorized" });
    try {
        const { eventId, action } = req.body;
        if (!['approved', 'rejected'].includes(action)) {
            return res.status(400).json({ error: "Invalid action." });
        }
        const updatedEvent = await Event.findByIdAndUpdate(eventId, { status: action }, { new: true });
        if (!updatedEvent) return res.status(404).json({ error: "Event not found." });
        res.json({ message: `Event has been successfully ${action}.` });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/events/approved", async (req, res) => {
    try {
        const approvedEvents = await Event.find({ status: 'approved' })
            .sort({ date: 1 })
            .populate('club', 'name');
        res.json(approvedEvents);
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

