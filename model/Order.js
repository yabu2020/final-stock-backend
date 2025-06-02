const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true }, 
  branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true }, 
  branchManagerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true }, 
  dateOrdered: { type: Date, default: Date.now },
  status: { type: String, default: 'Pending' } 
});

module.exports = mongoose.model('Order', OrderSchema);