const mongoose = require('mongoose');

const clubSchema = new mongoose.Schema({
  name: String,
  slug: { type: String, unique: true, required: true },
  description: String, // <-- add this
  image: String,       // <-- add this (e.g., "Aalap.png")
  headUsername: { type: String, unique: true },
  password: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
  pendingRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }]
});

module.exports = mongoose.model('Club', clubSchema);

