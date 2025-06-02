const mongoose = require('mongoose');

const CategorySchema = new mongoose.Schema({
  code: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  branchManagerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Employee', 
    required: true 
  }, 
}, { timestamps: true });

const CategoryModel = mongoose.model("Category", CategorySchema);

module.exports = CategoryModel;