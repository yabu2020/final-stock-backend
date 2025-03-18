const mongoose = require("mongoose");

const AssignmentSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product', // Reference to the Product model
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
    min: 1, // Ensure quantity is at least 1
  },
  totalPrice: {
    type: Number,
    required: true,
    min: 0.01, // Ensure totalPrice is positive
  },
  costPrice: { 
    type: Number,
  },
  dateAssigned: { 
    type: Date, 
    default: Date.now 
  },
  status: { 
    type: String, 
    enum: ['Available', 'Low Stock', 'Out Of Stock'], // Only allow these values
  },
  branchManagerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Employee', // Reference to the BranchManager model (if applicable)
    required: true, // Ensure every assignment is linked to a branch manager
  },
}, { timestamps: true });

module.exports = mongoose.model("Assignment", AssignmentSchema);