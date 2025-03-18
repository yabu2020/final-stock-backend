const mongoose = require('mongoose');

const CategorySchema = new mongoose.Schema({
  code: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  branchManagerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Employee', 
    required: true 
  }, // Link to the branch manager who created the category
}, { timestamps: true });

const CategoryModel = mongoose.model("Category", CategorySchema);

module.exports = CategoryModel;