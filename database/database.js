const mongoose = require("mongoose");

exports.connectDB = async () => {
  try {
    await mongoose.connect("mongodb://127.0.0.1:27017/userDB");
    console.log("Database Connected.");
  } catch (error) {
    console.log(error.message);
  }
};

// Mongodb Schema
const userSchema = new mongoose.Schema({
  userName: {
    required: true,
    type: String,
  },
  password: String,
});
exports.User = mongoose.model("User", userSchema);
