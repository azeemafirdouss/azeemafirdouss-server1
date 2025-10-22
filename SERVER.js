require('dotenv').config();

// --- Debug dotenv ---
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
const bcrypt = require("bcryptjs");
const { authenticateToken } = require("./middleware");
const Event = require('./models/eventModel');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || "temp_secret";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/kmit-club";
app.use(bodyParser.json());

app.use(cors({
  origin: "https://azeemafirdouss.github.io",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Serve frontend files (optional for testing)
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// MongoDB connection
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// Health endpoint
app.get('/', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// --- Safety for process errors ---
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
});

// --- Validation helpers ---
const validateStudentRollNo = (rollNo) => /^(22|23|24|25)BD1A05[A-G][0-9]$/.test(rollNo);
const validateFacultyEmail = (email) => /^[A-Za-z]{5,15}[0-9]{0,3}@gmail\.com$/.test(email);
const validateFacultyName = (name) => /^[A-Za-z]{1,20}$/.test(name);
const validateFacultyPassword = (password) => /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*]).{10,}$/.test(password);
const validateClubPassword = (password) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/.test(password);
const validateClubHeadUsername = (username) => /^[A-Za-z]+-Head$/i.test(username);
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// --- Schemas ---
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
  headUsername: { type: String, unique: true, sparse: true },
  password: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
  pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
  description: String,
  image: String
});
const Club = mongoose.model("Club", clubSchema);

// --- REGISTER ---
app.post("/register", async (req, res) => {
  try {
    const { role } = req.body;

    // --- Student Registration ---
    if (role === "student") {
      const { studentUsername, studentPassword } = req.body;
      if (!validateStudentRollNo(studentUsername))
        return res.status(400).json({ error: "❌ Invalid Roll No format. Use format like: 23BD1A05C7" });
      if (studentPassword !== studentUsername)
        return res.status(400).json({ error: "❌ Password must match Roll No" });
      if (await Student.findOne({ username: studentUsername }))
        return res.status(400).json({ error: "❌ Student already exists" });

      const student = new Student({
        username: studentUsername,
        password: studentPassword,
        name: studentUsername,
        rollNumber: studentUsername
      });
      await student.save();
      return res.json({ message: "✅ Student registration successful" });
    }

    // --- Faculty Registration ---
    if (role === "faculty") {
      const { facultyEmail, facultyPassword, name } = req.body;
      if (!validateFacultyEmail(facultyEmail))
        return res.status(400).json({ error: "❌ Invalid email format." });
      if (!validateFacultyName(name))
        return res.status(400).json({ error: "❌ Invalid name format." });
      if (!validateFacultyPassword(facultyPassword))
        return res.status(400).json({ error: "❌ Weak password." });
      if (await Faculty.findOne({ username: facultyEmail }))
        return res.status(400).json({ error: "❌ Faculty already exists" });

      const faculty = new Faculty({
        username: facultyEmail,
        password: facultyPassword,
        name,
        email: facultyEmail
      });
      await faculty.save();
      return res.json({ message: "✅ Faculty registration successful" });
    }

    // --- Club Head Registration (auto club assignment) ---
    if (role === "clubhead") {
      const { clubUsername, clubPassword } = req.body;

      if (!clubUsername || !clubPassword)
        return res.status(400).json({ error: "❌ Please fill in all fields." });
      if (!validateClubHeadUsername(clubUsername))
        return res.status(400).json({ error: "❌ Invalid club username format. Use: Clubname-Head" });
      if (!validateClubPassword(clubPassword))
        return res.status(400).json({ error: "❌ Weak password." });

      const baseClubName = clubUsername.replace(/-head$/i, "").trim();

      // Find by name or slug
      const club = await Club.findOne({
        $or: [
          { name: { $regex: new RegExp(`^${baseClubName}$`, "i") } },
          { slug: { $regex: new RegExp(`^${baseClubName}$`, "i") } }
        ]
      });

      if (!club)
        return res.status(400).json({ error: `❌ No club found for "${baseClubName}"` });

      // If already has a head
      if (club.headUsername && club.headUsername !== clubUsername)
        return res.status(400).json({ error: `❌ This club already has a head (${club.headUsername}).` });

      // Assign head automatically
      if (!club.headUsername) {
        club.headUsername = clubUsername;
        club.password = clubPassword;
        await club.save();
      }

      // Prevent duplicate ClubHead model
      if (await ClubHead.findOne({ username: clubUsername }))
        return res.status(400).json({ error: "❌ This club head already exists." });

      const clubHead = new ClubHead({
        username: clubUsername,
        password: clubPassword,
        name: `${club.name} Head`,
        club: club._id
      });
      await clubHead.save();

      return res.json({ message: `✅ Club Head registered successfully for ${club.name}!` });
    }

    // --- Admin Registration ---
    if (role === "admin") {
      const { adminId, adminPassword } = req.body;
      if (!/^[a-zA-Z0-9]{4,20}$/.test(adminId))
        return res.status(400).json({ error: "❌ Invalid Admin ID format." });
      if (!validateClubPassword(adminPassword))
        return res.status(400).json({ error: "❌ Weak password." });
      if (await Admin.findOne({ username: adminId }))
        return res.status(400).json({ error: "❌ Admin already exists" });

      const admin = new Admin({
        username: adminId,
        password: adminPassword,
        name: "Admin " + adminId
      });
      await admin.save();
      return res.json({ message: "✅ Admin registration successful" });
    }

    res.status(400).json({ error: "❌ Invalid role" });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "❌ Server error during registration" });
  }
});

// --- LOGIN ---
app.post("/login", async (req, res) => {
  try {
    let { role, username, password } = req.body || {};
    username = (username || '').trim();

    let userModel;
    if (role === "student") userModel = Student;
    else if (role === "faculty") userModel = Faculty;
    else if (role === "clubhead") userModel = ClubHead;
    else if (role === "admin") {
      if (username === "admin" && password === "Admin123$")
        return res.json({
          token: jwt.sign({ id: "admin", role: "admin", username }, JWT_SECRET, { expiresIn: "1h" }),
          role: "admin"
        });
      else return res.status(401).json({ error: "Invalid admin credentials" });
    }

    const user = await userModel.findOne({
      username: { $regex: `^${escapeRegex(username)}$`, $options: 'i' }
    });

    if (!user || user.password !== password)
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role, username: user.username, name: user.name },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token, role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Dashboards, Club join, Events ---
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
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/clubhead/dashboard", authenticateToken, async (req, res) => {
  try {
    const club = await Club.findOne({ headUsername: req.user.username })
      .populate("members", "username")
      .populate("pendingRequests", "username");

    if (!club) return res.json({ error: "No club found for this club head." });
    res.json(club);
  } catch (err) {
    console.error("Dashboard error:", err);
    res.json({ error: "Server error while loading dashboard." });
  }
});

app.post("/student/join-club", authenticateToken, async (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Unauthorized" });
  try {
    const { clubId } = req.body;
    const studentId = req.user.id;
    await Club.findByIdAndUpdate(clubId, { $addToSet: { pendingRequests: studentId } });
    await Student.findByIdAndUpdate(studentId, { $addToSet: { pendingRequests: clubId } });
    res.json({ message: "Request sent successfully!" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// --- Club Head event management ---
app.post("/clubhead/events", authenticateToken, async (req, res) => {
  if (req.user.role !== "clubhead") return res.status(403).json({ error: "Unauthorized" });
  try {
    const { title, description, date } = req.body;
    const clubHead = await ClubHead.findById(req.user.id);
    if (!clubHead || !clubHead.club)
      return res.status(404).json({ error: "Could not find the club for this user." });

    const newEvent = new Event({
      title, description, date, club: clubHead.club, status: 'pending'
    });
    await newEvent.save();
    res.status(201).json({ message: "Event proposal submitted successfully!" });
  } catch (err) {
    res.status(500).json({ error: "Server error while creating event." });
  }
});

app.get("/clubhead/my-events", authenticateToken, async (req, res) => {
  if (req.user.role !== "clubhead") return res.status(403).json({ error: "Unauthorized" });
  const clubHead = await ClubHead.findById(req.user.id);
  const events = await Event.find({ club: clubHead.club });
  res.json(events);
});

// --- Faculty event review ---
app.get("/faculty/dashboard", authenticateToken, async (req, res) => {
  if (req.user.role !== "faculty") return res.status(403).json({ error: "Unauthorized" });
  try {
    const pendingEvents = await Event.find({ status: 'pending' }).populate('club', 'name');
    const clubs = await Club.find({}).populate('members', 'username');
    const students = await Student.find({}, 'username');
    const clubHeads = await ClubHead.find({}, 'username');
    const allUsers = [
      ...students.map(s => ({ username: s.username, role: 'Student' })),
      ...clubHeads.map(ch => ({ username: ch.username, role: 'Club Head' }))
    ];
    res.json({ pendingEvents, clubs, allUsers });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/faculty/events/respond", authenticateToken, async (req, res) => {
  if (req.user.role !== "faculty") return res.status(403).json({ error: "Unauthorized" });
  try {
    const { eventId, action } = req.body;
    if (!['approved', 'rejected'].includes(action))
      return res.status(400).json({ error: "Invalid action." });
    const updatedEvent = await Event.findByIdAndUpdate(eventId, { status: action }, { new: true });
    if (!updatedEvent) return res.status(404).json({ error: "Event not found." });
    res.json({ message: `Event has been successfully ${action}.` });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/events/approved", async (req, res) => {
  try {
    const approvedEvents = await Event.find({ status: 'approved' }).sort({ date: 1 }).populate('club', 'name');
    res.json(approvedEvents);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --- Debug route ---
app.get("/debug/clubs", async (req, res) => {
  const clubs = await Club.find({}, "name slug headUsername");
  res.json(clubs);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
