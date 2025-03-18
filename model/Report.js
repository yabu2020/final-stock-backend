const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date,
    required: true
  },
  totalSales: {
    type: Number,
    required: true
  },
  profitOrLoss: {
    type: Number,
    required: true
  },
  reportData: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
      name:String,
      quantity: Number,
      totalPrice: Number,
      dateAssigned: Date,
      stockLevel: Number, // Already added stock level
      status: {
        type: String,
        enum: ['Available', 'Low Stock', 'Out Of Stock'],
      },
    }
  ],
  branchManagerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Employee", // Reference to the BranchManager model
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Report', reportSchema);
