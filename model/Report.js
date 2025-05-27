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
      name: String,
      quantity: Number,
      purchasePrice: Number,
      salePrice: Number,
      totalPrice: Number,
      date: { type: Date, required: true }, // Unified date field
      stockLevel: Number,
      status: {
        type: String,
        enum: ['Available', 'Low Stock', 'Out Of Stock'],
        default: 'Available'
      },
      type: { type: String, enum: ['Order', 'Sale'], required: true } // Added type field
    }
  ],
  branchManagerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Employee",
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  // In your Report model
status: {
  type: String,
  enum: ['draft', 'submitted', 'reviewed', 'approved'],
  default: 'draft'
},
  sentToAdmin: {
    type: Boolean,
    default: false
  },
  adminNotes: String,
});

// Add middleware to handle date conversion
reportSchema.post('init', function(doc) {
  if (doc.reportData) {
    doc.reportData.forEach(item => {
      if (item.date && !(item.date instanceof Date)) {
        item.date = new Date(item.date);
      }
    });
  }
  return doc;
});

reportSchema.set('toJSON', {
  transform: function(doc, ret) {
    if (ret.reportData) {
      ret.reportData.forEach(item => {
        if (item.date) {
          item.date = item.date.toISOString();
        }
      });
    }
    return ret;
  }
});

module.exports = mongoose.model('Report', reportSchema);