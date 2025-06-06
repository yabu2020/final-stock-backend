const mongoose = require("mongoose");

const BranchSchema = new mongoose.Schema({
  branchName: { type: String, required: true, unique: true },
  location: { type: String, required: true },
  manager: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Employee",
    required: false,
    unique: true, 
    sparse: true, 
  },
});

const BranchModel = mongoose.model("Branch", BranchSchema);

module.exports = BranchModel;
