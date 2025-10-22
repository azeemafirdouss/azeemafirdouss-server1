const mongoose = require("mongoose");

const studentSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  clubs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Club" }]
});

module.exports = mongoose.model("Student", studentSchema);
