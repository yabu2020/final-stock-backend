const mongoose = require("mongoose");

const EmployeeSchema = new mongoose.Schema({
  type: { type: String, required: true, enum: ["employee", "user"] },
  role: { type: String, required: false },
  name: { type: String, required: true },
  phone: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: false },
  address: { type: String, required: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: false }, 
  securityQuestion: { type: String, required: false }, 
  securityAnswer: { type: String, required: false }, 
});

const EmployeeModel = mongoose.model("Employee", EmployeeSchema);
module.exports = EmployeeModel;