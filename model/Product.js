const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  purchaseprice: { type: Number, required: true },
  saleprice: { type: Number, required: true },
  quantity: { type: Number, default: 1 },
  description: { type: String },
  quantityType: {
    type: String,
    enum: ["whole", "pieces"],
    default: "whole",
  },
  status: {
    type: String,
    enum: ["Available", "Low Stock", "Out Of Stock"],
    default: "Available",
  },
  category: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Category', 
    required: true 
  },
  branchManagerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Employee', 
    required: true 
  },
  image: { type: String }, // Add this field for the image path
}, { timestamps: true });

const ProductModel = mongoose.model("Product", ProductSchema);

module.exports = ProductModel;