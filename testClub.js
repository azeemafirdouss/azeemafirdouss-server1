const mongoose = require("mongoose");
const Club = require("./models/Club");

async function test() {
  try {
    await mongoose.connect("mongodb://127.0.0.1:27017/kmit-club");
    console.log("✅ Connected to MongoDB");

    const c = await Club.findOne({ headUsername: "Mudra-head" });
    console.log("Club Found:", c);

  } catch (err) {
    console.error("❌ Error:", err);
  } finally {
    mongoose.connection.close();
  }
}

test();
