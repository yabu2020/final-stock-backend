const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true }, // User who placed the order
  branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true }, // Branch where the product belongs
  branchManagerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true }, // Manager of the branch
  dateOrdered: { type: Date, default: Date.now },
  status: { type: String, default: 'Pending' } // Status field for tracking order status (e.g., Confirmed, Rejected)
});

module.exports = mongoose.model('Order', OrderSchema);