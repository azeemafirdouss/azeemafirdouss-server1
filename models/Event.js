// const mongoose = require("mongoose");

// const eventSchema = new mongoose.Schema({
//   title: String,
//   date: Date
// });

// module.exports = mongoose.model("Event", eventSchema);
const eventSchema = new mongoose.Schema({
  title: String,
  description: String,
  date: Date,
  status: { type: String, default: "pending" }, // so your dashboard color logic works
  club: { type: mongoose.Schema.Types.ObjectId, ref: "Club" } // link to club
});
