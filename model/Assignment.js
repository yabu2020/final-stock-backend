const mongoose = require("mongoose");

const AssignmentSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product', 
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
    min: 1, 
  },
  totalPrice: {
    type: Number,
    required: true,
    min: 0.01, 
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
    enum: ['Available', 'Low Stock', 'Out Of Stock'], 
  },
  branchManagerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Employee',
    required: true, 
  },
}, { timestamps: true });

module.exports = mongoose.model("Assignment", AssignmentSchema);