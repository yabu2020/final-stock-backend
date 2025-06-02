require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt"); 
const EmployeeModel = require("./model/Employee");
const ProductModel = require("./model/Product");
const AssignmentModel = require("./model/Assignment");
const OrderModel = require('./model/Order'); 
const ReportModel = require('./model/Report'); 
const CategoryModel = require("./model/Category");
const BranchModel = require("./model/Branch");
const authenticateToken = require('./model/authenticateToken'); 
const multer = require("multer");
const jwt = require('jsonwebtoken'); 
const jwtSecret = process.env.JWT_SECRET;
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const app = express();


const normalizePhone = (phone) => phone.trim().toLowerCase();
const normalizename = (name) => name.trim().toLowerCase();


app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173',  
  credentials: true,                
}));
app.use(bodyParser.json());
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use("/uploads", express.static(uploadDir));
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`); 
  },
});

const upload = multer({ storage });
app.use(express.json());

mongoose.connect(
  "mongodb+srv://yeabsiraayalew6:yabu2020@cluster0.s3vfs.mongodb.net/",
   
).then(()=>{
  console.log("Database connected successfully");
})
.catch((err)=>{
  console.error("Error connecting to MongoDB:", err);
})
const validatePassword = (password) => {
  if (password.length < 6) {
    return "Password must be at least 6 characters long";
  }
  const complexityRe = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
  if (!complexityRe.test(password)) {
    return "Password must contain at least one letter and one number";
  }

  return null;
};

app.post("/api/pay", async (req, res) => {
  try {
    const chapaUrl = "https://api.chapa.co/v1/transaction/initialize";
    const secretKey = "CHASECK_TEST-z8hnOz0YewilQrzs1CSujy2KBoBXR9i6"; // your test secret key

    const payload = {
      amount: "100",
      currency: "ETB",
      email: "testuser@example.com",
      first_name: "Test",
      last_name: "User",
      tx_ref: "tx-" + Date.now(),
      callback_url: "https://yourdomain.com/callback",
      return_url: "https://yourdomain.com/success",
      customization: {
        title: "Final Project",
        description: "Test Payment"
      }
    };

    const response = await axios.post(chapaUrl, payload, {
      headers: {
        Authorization: `Bearer ${secretKey}`,
        "Content-Type": "application/json"
      }
    });

    res.json({ checkoutUrl: response.data.data.checkout_url });

  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: "Payment initialization failed" });
  }
});

app.post('/api/payments/initiate', async (req, res) => {
  const { amount, email, first_name, last_name, tx_ref, return_url } = req.body;

  try {
    const response = await axios.post(
      'https://api.chapa.co/v1/transaction/initialize',
      {
        amount,
        currency: 'ETB',
        email,
        first_name,
        last_name,
        tx_ref,
        return_url,
        callback_url: return_url, 
        customization: {
          title: "Your Store Name",
          description: "Payment for your order"
        }
      },
      {
        headers: {
          Authorization: 'Bearer CHASECK_TEST-z8hnOz0YewilQrzs1CSujy2KBoBXR9i6',
          'Content-Type': 'application/json'
        }
      }
    );

    res.json({ checkout_url: response.data.data.checkout_url });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

app.post('/api/payments/verify', async (req, res) => {
  try {
    const { tx_ref } = req.body;

    if (!tx_ref) {
      return res.status(400).json({
        success: false,
        error: 'Transaction reference is required'
      });
    }

    console.log(`Verifying payment with reference: ${tx_ref}`);

    const response = await axios.get(
      `https://api.chapa.co/v1/transaction/verify/${tx_ref}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.CHAPA_SECRET_KEY || 'CHASECK_TEST-z8hnOz0YewilQrzs1CSujy2KBoBXR9i6'}`
        },
        timeout: 10000 
      }
    );

    console.log('Chapa verification response:', response.data);

    if (response.data.status === 'success') {
      return res.json({
        success: true,
        data: {
          tx_ref: response.data.tx_ref,
          amount: response.data.amount,
          currency: response.data.currency,
          status: response.data.status,
          created_at: response.data.created_at
        }
      });
    }

    return res.status(400).json({
      success: false,
      error: 'Payment not completed',
      details: response.data
    });

  } catch (error) {
    console.error('Payment verification error:', error);
        const errorMessage = error.response?.data?.message || 
                       error.message || 
                       'Payment verification failed';

    return res.status(500).json({
      success: false,
      error: errorMessage,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.post("/", async (req, res) => {
  const { name, password } = req.body;

  if (!name) {
    return res.status(400).json({ message: "Name is required" });
  }
  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  try {
    const user = await EmployeeModel.findOne({ name });

    if (!user) {
      return res
        .status(404)
        .json({ message: "No record found with this name" });
    }
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }
    const token = jwt.sign(
      { _id: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' } 
    );

    res.json({
      message: "Login successful",
      token, 
      user: {
        _id: user._id,
        name: user.name,
        role: user.role, 
        phone: user.phone,
        address: user.address
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "An error occurred during login" });
  }
});
app.post("/adduser", async (req, res) => {
  const { name, role,phone, address, password } = req.body;

  try {
    if (!name || !phone || !address || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    const existingUser = await EmployeeModel.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ error: "Duplicate phone" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new EmployeeModel({
      type: "employee",
      role: "user",
      name,
      phone,
      password: hashedPassword,
      address,
    });

    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (err) {
    console.error("Error adding user:", err.message);
    if (err.code === 11000) {
      res.status(400).json({ error: "Duplicate phone" });
    } else {
      res.status(500).json({ error: "Error adding user" });
    }
  }
});

function isLettersOnly(str) {
  return /^[A-Za-z\s]+$/.test(str);
}

function isValidPhone(phone) {
  return /^(09|07)\d{8}$/.test(phone);
}

function isValidAddress(address) {
  return /[A-Za-z]/.test(address); 
}



app.post("/signup", async (req, res) => {
  const { name, phone, password, address } = req.body;

  try {
    const normalizedPhone = phone.trim().toLowerCase();
    const normalizedName = name.trim().toLowerCase();

    if (!isLettersOnly(normalizedName)) {
      return res.status(400).json({ error: "Name must contain letters only" });
    }
    if (!isValidPhone(normalizedPhone)) {
      return res.status(400).json({ error: "Phone number must start with 09 or 07 and be 10 digits long" });
    }
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: "Address must contain letters" });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }
    const userWithName = await EmployeeModel.findOne({ name: normalizedName });
    if (userWithName) {
      return res.status(400).json({ error: "User with this name is already registered" });
    }
    const userWithPhone = await EmployeeModel.findOne({ phone: normalizedPhone });
    if (userWithPhone) {
      return res.status(400).json({ error: "Phone number is already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new EmployeeModel({
      type: "employee",
      role: "user",
      name: normalizedName, 
      phone: normalizedPhone, 
      password: hashedPassword,
      address,
    });

    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (err) {
    console.error("Error during signup:", err);
    if (err.code === 11000) {
      res.status(400).json({ error: "Duplicate entry for name or phone number" });
    } else {
      res.status(500).json({ error: "Error signing up" });
    }
  }
});


app.get("/users", async (req, res) => {
  const { type } = req.query; 

  try {
    let query = {};
    if (type) {
      query.type = type; 
    }

    const users = await EmployeeModel.find(query, "name role phone address");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Error fetching users" });
  }
});



app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  EmployeeModel.findByIdAndDelete(id)
    .then((deletedUser) => {
      if (!deletedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json({ message: "User deleted successfully" });
    })
    .catch((err) =>
      res
        .status(500)
        .json({ message: "Error deleting user", error: err.message })
    );
});

app.put("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, address } = req.body;

    if (!name || !phone || !address) {
      return res.status(400).json({
        success: false,
        message: "Name, phone, and address are required"
      });
    }
    const hasLetters = /[a-zA-Z]/.test(address);
    if (!hasLetters) {
      return res.status(400).json({
        success: false,
        message: "Address must include letters"
      });
    }

    const updatedUser = await EmployeeModel.findByIdAndUpdate(
      id,
      { name, phone, address },
      {
        new: true,
        runValidators: true
      }
    );

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.json({
      success: true,
      user: updatedUser,
      message: "Profile updated successfully"
    });
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({
      success: false,
      message: "Error updating user",
      error: err.message
    });
  }
});



app.get("/users/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const user = await EmployeeModel.findById(req.params.id)
      .select('-password') 
      .lean(); 
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get("/employees", async (req, res) => {
  try {
    const employees = await EmployeeModel.find({ type: "employee" }, "name role phone address");
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: "Error fetching employees" });
  }
});

app.post("/addemployee", async (req, res) => {
  const { role, name, phone, address, password } = req.body;

  if (!["user", "Admin", "manager", "asset approver"].includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    const existingEmployee = await EmployeeModel.findOne({ name });
    if (existingEmployee) {
      return res.status(400).json({ error: "Employee is already registered with this name" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const newEmployee = new EmployeeModel({
      type: "employee",
      role,
      name,
      phone,
      address,
      password: hashedPassword,
    });

    const savedEmployee = await newEmployee.save();
    res.json(savedEmployee);
  } catch (err) {
    console.error("Error adding employee:", err);
    if (err.code === 11000) {
      res.status(400).json({ error: "Duplicate phone" });
    } else {
      res.status(500).json({ error: "Error adding employee" });
    }
  }
});


app.delete("/employees/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const deletedEmployee = await EmployeeModel.findByIdAndDelete(id);
    if (!deletedEmployee) {
      return res.status(404).json({ error: "Employee not found" });
    }
    res.json({ message: "Employee deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Error deleting employee" });
  }
});


app.post("/addbranch", async (req, res) => {
  const { branchName, location, managerId } = req.body;

  try {
    if (!branchName || !location || !managerId) {
      return res.status(400).json({ error: "Branch name, location, and manager are required" });
    }
    const existingBranch = await BranchModel.findOne({ branchName });
    if (existingBranch) {
      return res.status(400).json({ error: "Branch already exists" });
    }
    const existingManagerAssignment = await BranchModel.findOne({ manager: managerId });
    if (existingManagerAssignment) {
      return res.status(400).json({ error: "This manager is already assigned to another branch" });
    }
    const newBranch = new BranchModel({
      branchName,
      location,
      manager: managerId,
    });

    const savedBranch = await newBranch.save();
    res.status(201).json(savedBranch);
  } catch (err) {
    console.error("Error creating branch:", err.message, err.stack);
    res.status(500).json({ error: "Error creating branch", details: err.message });
  }
});


app.put("/branches/:id", async (req, res) => {
  const { id } = req.params;
let updateData = req.body;

if (updateData.managerId) {
  updateData.manager = updateData.managerId;
  delete updateData.managerId;
}

  console.log("Updating branch:", id);
  console.log("With data:", updateData);

  try {
    const updatedBranch = await BranchModel.findByIdAndUpdate(id, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedBranch) {
      return res.status(404).json({ error: "Branch not found" });
    }

    res.json(updatedBranch);
  } catch (err) {
    console.error("Error updating branch:", err.message);
    res.status(500).json({
      error: "Error updating branch",
      details: err.message,
    });
  }
});


app.delete("/branches/:id", async (req, res) => {
  const { id } = req.params;

  console.log("Deleting branch with ID:", id);

  try {
    const deletedBranch = await BranchModel.findByIdAndDelete(id);

    if (!deletedBranch) {
      return res.status(404).json({ error: "Branch not found" });
    }

    res.json({ message: "Branch deleted successfully" });
  } catch (err) {
    console.error("Error deleting branch:", err.message);
    res.status(500).json({
      error: "Error deleting branch",
      details: err.message,
    });
  }
});


app.put("/assignmanager/:branchId", async (req, res) => {
  const { managerId } = req.body;

  try {
    const employee = await EmployeeModel.findById(managerId);
    if (!employee || employee.role !== "manager") {
      return res.status(400).json({ error: "Invalid manager ID" });
    }

    const updatedBranch = await BranchModel.findByIdAndUpdate(
      req.params.branchId,
      { manager: managerId },
      { new: true }
    );

    res.json(updatedBranch);
  } catch (err) {
    res.status(500).json({ error: "Error assigning branch manager" });
  }
});


app.get("/branch-by-manager/:managerId", async (req, res) => {
  const { managerId } = req.params;

  try {
    const branch = await BranchModel.findOne({ manager: managerId });
    if (!branch) {
      return res.status(404).json({ error: "No branch assigned to this manager" });
    }
    res.json(branch);
  } catch (err) {
    console.error("Error fetching branch by manager:", err.message);
    res.status(500).json({ error: "Error fetching branch details" });
  }
});
app.get("/branches", async (req, res) => {
  try {
    const branches = await BranchModel.find().populate("manager", "name phone");
    res.json(branches);
  } catch (err) {
    res.status(500).json({ error: "Error fetching branches" });
  }
});

app.get("/api/stats", async (req, res) => {
  try {
    const [
      totalUsers,
      totalAdmins,
      totalManagers,
      totalBranches,
      totalReports
    ] = await Promise.all([
      EmployeeModel.countDocuments({ role: "user" }),
      EmployeeModel.countDocuments({ role: "admin" }),
      EmployeeModel.countDocuments({ role: "manager" }),
      BranchModel.countDocuments(),
       ReportModel.countDocuments(), 
    ]);

    const totalEmployees = totalAdmins + totalManagers;
    res.json({
      totalUsers,
      totalEmployees,
      totalBranches,
      totalReports,
    });
  } catch (err) {
    console.error("Error fetching stats:", err);
    res.status(500).json({ error: "Failed to fetch dashboard stats" });
  }
});


app.get("/api/user-breakdown", async (req, res) => {
  try {
    const breakdown = await EmployeeModel.aggregate([
      {
        $group: {
          _id: "$role",
          count: { $sum: 1 }
        }
      }
    ]);

    const formattedBreakdown = breakdown.map(item => ({
      name: item._id,
      value: item.count
    }));

    res.json(formattedBreakdown);
  } catch (err) {
    console.error("Error fetching user breakdown:", err);
    res.status(500).json({ error: "Failed to fetch breakdown" });
  }
});


app.get("/api/revenue-stats", async (req, res) => {
  try {
    const currentYear = new Date().getFullYear();
        const monthlyRevenue = await OrderModel.aggregate([
      {
        $match: {
          status: "Confirmed", 
          dateOrdered: {
            $gte: new Date(`${currentYear}-01-01`),
            $lte: new Date(`${currentYear}-12-31`)
          }
        }
      },
      {
        $group: {
          _id: { $month: "$dateOrdered" },
          totalRevenue: { $sum: "$totalPrice" }
        }
      },
      {
        $project: {
          month: "$_id",
          revenue: "$totalRevenue",
          _id: 0
        }
      },
      {
        $sort: { month: 1 }
      }
    ]);

    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    
    const formattedRevenue = monthlyRevenue.map(item => ({
      month: monthNames[item.month - 1],
      revenue: item.revenue
    }));
    const completeRevenue = monthNames.map((month, index) => {
      const found = formattedRevenue.find(item => item.month === month);
      return found || { month, revenue: 0 };
    });

    res.json(completeRevenue);
  } catch (err) {
    console.error("Error fetching revenue stats:", err);
    res.status(500).json({ error: "Failed to fetch revenue stats" });
  }
});


app.get("/api/admin/reports", async (req, res) => {
  try {
    const reports = await ReportModel.find({ 
      sentToAdmin: true 
    })
    .sort({ sentAt: -1 })
    .populate('branchManagerId', 'name email');
    
    res.json(reports);
  } catch (err) {
    console.error("Error fetching admin reports:", err);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});



app.get('/api/manager/stats', async (req, res) => {
  try {
    const { managerId } = req.query;
    
    if (!managerId) {
      return res.status(400).json({ error: 'Manager ID is required' });
    }

    const today = new Date();
    const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    const startOfYear = new Date(today.getFullYear(), 0, 1);

    const branch = await BranchModel.findOne({ manager: managerId });
    if (!branch) {
      return res.status(404).json({ error: 'Branch not found for this manager' });
    }

    const [
      totalOrders,
      totalReports,
      monthlyEarnings
    ] = await Promise.all([
      OrderModel.countDocuments({
        branchId: branch._id,
        status: 'Confirmed',
        dateOrdered: { $gte: startOfMonth }
      }),

      ReportModel.countDocuments({
        branchManagerId: managerId,
        sentToAdmin: true
      }),

      OrderModel.aggregate([
        {
          $match: {
            branchId: branch._id,
            status: 'Confirmed',
            dateOrdered: { $gte: startOfYear }
          }
        },
        {
          $group: {
            _id: { $month: '$dateOrdered' },
            earnings: { $sum: '$totalPrice' }
          }
        },
        { $sort: { '_id': 1 } }
      ])
    ]);

    res.json({
      stats: {
        orders: totalOrders,
        reports: totalReports
      },
      monthlyEarnings: monthlyEarnings.map(item => ({
        month: item._id,
        earnings: item.earnings || 0
      }))
    });

  } catch (error) {
    console.error('Error fetching manager stats:', error);
    res.status(500).json({ error: 'Failed to fetch manager dashboard data' });
  }
});




app.get("/api/branch-manager/sales-breakdown", async (req, res) => {
  try {
    const branchManagerId = req.user._id;
    const salesBreakdown = await OrderModel.aggregate([
      {
        $match: { branchManagerId },
      },
      {
        $lookup: {
          from: "products",
          localField: "productId",
          foreignField: "_id",
          as: "product",
        },
      },
      {
        $unwind: "$product",
      },
      {
        $group: {
          _id: "$product.category",
          totalSales: {
            $sum: { $multiply: ["$quantity", "$price"] },
          }
                  },
      },
      {
        $project: {
          name: "$_id",
          value: "$totalSales",
        },
      },
    ]);

    res.json(salesBreakdown);
  } catch (err) {
    console.error("Error fetching sales breakdown:", err);
    res.status(500).json({ error: "Failed to fetch sales breakdown" });
  }
});


app.get("/api/branch-manager/net-income", async (req, res) => {
  try {
    const branchManagerId = req.user._id;
    const netIncome = await OrderModel.aggregate([
      {
        $match: { branchManagerId },
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } }, 
          earnings: { $sum: "$totalAmount" }, 
        },
      },
      {
        $project: {
          month: "$_id",
          earnings: 1,
          _id: 0,
        },
      },
    ]);

    res.json(netIncome);
  } catch (err) {
    console.error("Error fetching net income:", err);
    res.status(500).json({ error: "Failed to fetch net income" });
  }
});


app.get('/check-code', async (req, res) => {
  try {
    const { code, branchManagerId } = req.query;
    
    if (!code || !branchManagerId) {
      return res.status(400).json({ error: 'Code and branchManagerId are required' });
    }

    const existingCategory = await CategoryModel.findOne({ 
      code,
      branchManagerId 
    });

    res.json({ exists: !!existingCategory });
  } catch (error) {
    console.error('Error checking code:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/category', async (req, res) => {
  try {
    const { code, description, category, branchManagerId } = req.body;
    if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
      return res.status(400).json({ error: 'Invalid or missing branch manager ID.' });
    }
    const existingCategory = await CategoryModel.findOne({ 
      code,
      branchManagerId 
    });

    if (existingCategory) {
      return res.status(400).json({ error: 'This code already exists' });
    }
    if (/^\d+$/.test(category)) {
      return res.status(400).json({ error: 'Category cannot be only numbers' });
    }
    const newCategory = new CategoryModel({
      code,
      description,
      category,
      branchManagerId,
    });

    await newCategory.save();

    res.status(201).json({ message: 'Category registered successfully.' });
  } catch (error) {
    console.error('Error registering category:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/categories', async (req, res) => {
  try {
    const { branchManagerId } = req.query;

    if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
      return res.status(400).json({ error: 'Invalid or missing branch manager ID.' });
    }
    const categories = await CategoryModel.find({ branchManagerId });

    res.status(200).json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post("/addproduct", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { name, purchaseprice, saleprice, description, category } = req.body;
    const branchManagerId = req.user._id;
    if (!req.file) {
      return res.status(400).json({ message: "Image is required." });
    }
    const imagePath = `/uploads/${req.file.filename}`;

    if (!name || !purchaseprice || !saleprice || !category) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const purchasePrice = parseFloat(purchaseprice);
    const salePrice = parseFloat(saleprice);

    if (isNaN(purchasePrice) || isNaN(salePrice)) {
      return res.status(400).json({ message: "Invalid prices." });
    }

    const categoryExists = await CategoryModel.findById(category);
    if (!categoryExists) {
      return res.status(400).json({ message: "Category not found." });
    }

    const newProduct = new ProductModel({
      name,
      purchaseprice: purchasePrice,
      saleprice: salePrice,
      description,
      category: categoryExists._id,
      branchManagerId, 
      image: imagePath,
    });

    await newProduct.save();
    res.status(201).json({ message: "Product added successfully.", product: newProduct });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(400).json({ message: error.message });
  }
});
app.post("/buyproduct", async (req, res) => {
  try {
    const { productId, quantity, supplier } = req.body;

    if (!productId || !quantity ) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
      return res.status(400).json({ error: "Invalid quantity." });
    }

    const product = await ProductModel.findById(productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found." });
    }
    product.quantity += parsedQuantity;
    await product.save();

    res.status(201).json({ message: "Stock purchase recorded successfully.", product });
  } catch (error) {
    console.error("Error recording stock purchase:", error);
    res.status(400).json({ error: error.message });
  }
});

app.get("/productlist", async (req, res) => {
  const { search, branchManagerId } = req.query;
  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    console.error("Invalid or missing branch manager ID:", branchManagerId);
    return res.status(400).json({ message: "Invalid or missing branch manager ID." });
  }

  try {
    const objectIdBranchManagerId = new mongoose.Types.ObjectId(branchManagerId);
    const products = await ProductModel.aggregate([
      {
        $match: {
          branchManagerId: objectIdBranchManagerId,
          $or: [
            { name: { $regex: search || "", $options: 'i' } },
            { productno: { $regex: search || "", $options: 'i' } }
          ]
        }
      },
      {
        $group: {
          _id: "$category",
          products: {
            $push: {
              _id: "$_id",
              productno: "$productno",
              name: "$name",
              purchaseprice: "$purchaseprice",
              saleprice: "$saleprice",
              quantity: "$quantity",
              description: "$description",
              quantityType: "$quantityType",
              status: "$status",
              image: "$image", 
            }
          }
        }
      }
    ]);
    const stockAlerts = products.flatMap(group =>
      group.products.filter(product => product.status === "Low Stock" || product.status === "Out Of Stock")
    );

    res.json({
      products,
      stockAlerts: stockAlerts.length > 0 ? stockAlerts : null 
    });
  } catch (err) {
    console.error("Error fetching products:", err); 
    res.status(500).json({ message: "Error fetching products." });
  }
});


app.put("/updateproduct/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      productno,
      purchaseprice,
      saleprice,
      quantity,
      description,
      status,
      category 
    } = req.body;
    const updatedProduct = await ProductModel.findByIdAndUpdate(
      id,
      {
        name,
        productno,
        purchaseprice,
        saleprice,
        quantity,
        description,
        status, 
        category 
      },
      { new: true }
    );

    if (updatedProduct) {
      res.json(updatedProduct);
    } else {
      res.status(404).json({ message: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ message: "Error updating Product" });
  }
});


app.delete('/deleteproduct/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const product = await ProductModel.findById(productId);

    if (!product ) {
      return res.status(404).json({ message: 'Product  not found' });
    }
    await ProductModel.findByIdAndDelete(productId);

    return res.status(200).json({ message: 'Product deleted successfully' });
  } catch (error) {
    return res.status(500).json({ message: 'Server error', error: error.message });
  }
});


app.post("/sellproduct", async (req, res) => {
  const { productId, quantity, totalPrice, branchManagerId } = req.body;

  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    return res.status(400).json({ error: "Invalid branch manager ID" });
  }

  try {
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ error: "Invalid Product ID" });
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    const product = await ProductModel.findById(productId).session(session);
    if (!product) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: "Product not found" });
    }

    if (product.quantity < quantity) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({
        error: `Insufficient stock. Only ${product.quantity} units are available.`,
      });
    }
    const costPrice = product.purchaseprice * quantity;
    product.quantity -= quantity;
    if (product.quantity === 0) {
      product.status = 'Out Of Stock';
    } else if (product.quantity <= 5) {
      product.status = 'Low Stock';
    } else {
      product.status = 'Available';
    }

    await product.save({ session });

    const assignment = new AssignmentModel({
      product: productId,
      quantity,
      totalPrice,
      costPrice,
      dateAssigned: new Date(),
      branchManagerId,
    });
    
    await assignment.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ assignment, status: product.status });
  } catch (error) {
    console.error("Error assigning product:", error);
    res.status(500).json({ error: "Error assigning product", details: error.message });
  }
});


app.get("/assigned-products", async (req, res) => {
  const { branchManagerId } = req.query;

  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    return res.status(400).json({ error: "Invalid or missing branch manager ID." });
  }

  try {
    const assignments = await AssignmentModel.find({ branchManagerId })
      .populate('product')
      .exec();

    res.json(assignments);
  } catch (err) {
    console.error("Error fetching assigned products:", err);
    res.status(500).json({ message: "Error fetching assigned products." });
  }
});



app.post('/reports', async (req, res) => {
  const { startDate, endDate, branchManagerId } = req.body;

  if (!startDate || !endDate || !branchManagerId) {
    return res.status(400).json({ error: 'Start date, end date, and branch manager ID are required' });
  }

  try {
    const start = new Date(startDate);
    start.setHours(0, 0, 0, 0);
    
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999);

    console.log(`Querying between: ${start} and ${end}`);
    const orders = await OrderModel.find({
      dateOrdered: { $gte: start, $lte: end },
      branchManagerId: branchManagerId,
    }).populate('product').lean();

    console.log(`Found ${orders.length} orders`);
    console.log('Sample order:', orders.length > 0 ? orders[0] : null);

    const assignments = await AssignmentModel.find({
      dateAssigned: { $gte: start, $lte: end },
      branchManagerId: branchManagerId,
    }).populate('product').lean();

    console.log(`Found ${assignments.length} assignments`);
    console.log('Sample assignment:', assignments.length > 0 ? assignments[0] : null);
    const reportData = [
      ...orders.map(order => ({
        product: order.product?._id,
        name: order.product?.name || 'Unknown Product',
        type: "Order",
        quantity: Number(order.quantity) || 0,
        purchasePrice: Number(order.product?.purchaseprice) || 0,
        salePrice: Number(order.product?.saleprice) || 0,
        totalPrice: Number(order.totalPrice) || 0,
        date: order.dateOrdered,
        stockLevel: Number(order.product?.quantity) || 0,
        status: order.product?.status || 'Available'
      })),
      ...assignments.map(assignment => ({
        product: assignment.product?._id,
        name: assignment.product?.name || 'Unknown Product',
        type: "Sale",
        quantity: Number(assignment.quantity) || 0,
        purchasePrice: Number(assignment.product?.purchaseprice) || 0,
        salePrice: assignment.quantity > 0 
          ? Number(assignment.totalPrice) / Number(assignment.quantity)
          : 0,
        totalPrice: Number(assignment.totalPrice) || 0,
        date: assignment.dateAssigned,
        stockLevel: Number(assignment.product?.quantity) || 0,
        status: assignment.product?.status || 'Available'
      }))
    ];

    if (reportData.length === 0) {
      return res.status(404).json({ 
        error: 'No sales data found for the selected date range',
        query: {
          startDate: start,
          endDate: end,
          branchManagerId
        },
        counts: {
          orders: orders.length,
          assignments: assignments.length
        }
      });
    }

    const totalSales = reportData.reduce((sum, item) => sum + (item.totalPrice || 0), 0);
    const costPrice = reportData.reduce(
      (sum, item) => sum + ((item.purchasePrice || 0) * (item.quantity || 0)), 
      0
    );
    const profitOrLoss = totalSales - costPrice;

    const report = new ReportModel({
      startDate: start,
      endDate: end,
      totalSales,
      profitOrLoss,
      reportData,
      branchManagerId,
    });

    await report.save();
    res.status(201).json(report);

  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({ 
      error: "Error generating report", 
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});


app.get('/reports', async (req, res) => {
  const { branchManagerId } = req.query;

  if (!branchManagerId) {
    return res.status(400).json({ error: 'Branch manager ID is required' });
  }

  try {
    const reports = await ReportModel.find({ branchManagerId })
      .sort({ createdAt: -1 })
      .lean(); 
        const formattedReports = reports.map(report => ({
      ...report,
      reportData: report.reportData.map(item => ({
        ...item,
        date: item.date ? new Date(item.date).toISOString() : null,
        formattedDate: item.date ? new Date(item.date).toLocaleDateString() : 'N/A'
      }))
    }));

    res.json(formattedReports);
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ 
      error: "Error fetching reports",
      details: error.message 
    });
  }
});


app.get('/admin/reports', async (req, res) => {
  try {
    const reports = await ReportModel.find({ sentToAdmin: true })
      .populate('branchManagerId', 'name email')
      .sort({ createdAt: -1 });
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.post('/reports/:id/send-to-admin', async (req, res) => {
  try {
    const report = await ReportModel.findByIdAndUpdate(
      req.params.id,
      { 
        sentToAdmin: true,
        sentAt: new Date(),
        status: 'submitted'
      },
      { new: true }
    ).populate('branchManagerId', 'name email');
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    res.json({ 
      success: true,
      report 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.post('/admin/reports/:id/comment', async (req, res) => {
  const { comment } = req.body;
  await ReportModel.findByIdAndUpdate(
    req.params.id,
    { adminNotes: comment }
  );
  res.json({ success: true });
});



app.post('/orders', async (req, res) => {
  try {
    const { product, quantity, totalPrice, userId, branchManagerId, branchId, tx_ref } = req.body;
    const requiredFields = ['product', 'quantity', 'totalPrice', 'userId', 'branchManagerId', 'branchId', 'tx_ref'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        error: "Missing required fields",
        missingFields
      });
    }
    const existingOrder = await OrderModel.findOne({
      $or: [
        { tx_ref },
        { 
          product,
          userId,
          branchId,
          createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Orders in last 24 hours
        }
      ]
    });
    
    if (existingOrder) {
      return res.status(400).json({ 
        error: "Duplicate order detected",
        existingOrderId: existingOrder._id
      });
    }
    const order = new OrderModel({
      product,
      quantity,
      totalPrice,
      userId,
      branchManagerId,
      branchId,
      tx_ref,
      dateOrdered: new Date(),
      status: 'Pending',
      paymentStatus: req.body.paymentVerified ? 'Verified' : 'Pending'
    });

    await order.save();
    const populatedOrder = await OrderModel.findById(order._id)
      .populate('product')
      .populate('userId', 'name address phone')
      .populate('branchManagerId', 'name')
      .populate('branchId', 'branchName');

    res.status(201).json(populatedOrder);
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({
      error: "Error creating order",
      details: error.message,
    });
  }
});


app.get("/orders", (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }
  OrderModel.find({ userId: userId })
    .populate('product') 
    .populate('userId', 'name address phone') 
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: "Error fetching orders", message: err.message });
    });
});



app.get("/admin/orders", async (req, res) => {
  const { branchManagerId } = req.query;

  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    return res.status(400).json({ error: "Invalid or missing branch manager ID" });
  }

  try {
    const branches = await BranchModel.find({ manager: branchManagerId });
    const branchIds = branches.map(branch => branch._id);

    if (branchIds.length === 0) {
      return res.status(404).json({ error: "No branches found for this branch manager" });
    }
    const orders = await OrderModel.find({ branchId: { $in: branchIds } })
      .populate("userId", "name address phone")
      .populate("product");

    if (orders.length === 0) {
      return res.status(200).json([]); 
    }

    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders", details: error.message });
  }
});


app.patch('/admin/orders/:orderId/confirm', async (req, res) => {
  try {
    const { orderId } = req.params;

    const order = await OrderModel.findById(orderId).populate('product');
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (order.status === 'Confirmed') {
      return res.status(400).json({ error: "Order is already confirmed" });
    }
    if (order.status === 'Rejected') {
      return res.status(400).json({ error: "Cannot confirm a rejected order" });
    }

    if (!order.product) {
      return res.status(400).json({ error: "Product not found for this order" });
    }

    if (order.product.quantity < order.quantity) {
      return res.status(400).json({ 
        error: "Insufficient stock",
        details: {
          available: order.product.quantity,
          requested: order.quantity
        }
      });
    }

    order.product.quantity -= order.quantity;
    order.product.status =
      order.product.quantity === 0
        ? 'Out Of Stock'
        : order.product.quantity < 5
        ? 'Low Stock'
        : 'Available';

    await order.product.save();
    order.status = 'Confirmed';
    order.confirmedAt = new Date(); 
    await order.save();
    const updatedOrder = await OrderModel.findById(order._id)
      .populate('userId', 'name address phone')
      .populate('product');

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error confirming order:", error.message, error.stack);
    res.status(500).json({ 
      error: "Error confirming order", 
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});


app.patch('/admin/orders/:orderId/reject', async (req, res) => {
  try {
    const { orderId } = req.params;
    const order = await OrderModel.findById(orderId).populate('product');
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (order.status === 'Rejected') {
      return res.status(400).json({ error: "Order is already rejected" });
    }

    if (order.status === 'Confirmed') {
      order.product.quantity += order.quantity;
      order.product.status =
        order.product.quantity === 0
          ? 'Out Of Stock'
          : order.product.quantity < 5
          ? 'Low Stock'
          : 'Available';

      await order.product.save();
    }
    order.status = 'Rejected';
    order.rejectedAt = new Date(); 
    await order.save();
    const updatedOrder = await OrderModel.findById(order._id)
      .populate('userId', 'name address phone')
      .populate('product');

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error rejecting order:", error);
    res.status(500).json({ 
      error: "Error rejecting order", 
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});



app.get('/current_user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  res.json(req.session.user); 
});


app.post("/resetpassword", async (req, res) => {
  const { name, newPassword } = req.body;

  if (!name) {
    return res.status(400).json({ message: "Name is required" });
  }
  if (!newPassword) {
    return res.status(400).json({ message: "New password is required" });
  }

  const passwordError = validatePassword(newPassword);
  if (passwordError) {
    return res.status(400).json({ message: passwordError });
  }

  try {
    const user = await EmployeeModel.findOne({ name: name }); 

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "An error occurred while resetting the password." });
  }
});


app.post('/validate-security', async (req, res) => {
  const { name, securityQuestion, securityAnswer } = req.body;

  if (!name || !securityQuestion || !securityAnswer) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }

  try {
    const user = await EmployeeModel.findOne({ name });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    if (user.securityQuestion !== securityQuestion || user.securityAnswer !== securityAnswer) {
      return res.status(400).json({ success: false, message: 'Security question or answer is incorrect.' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error validating security question:', error);
    res.status(500).json({ success: false, message: 'An error occurred. Please try again.' });
  }
});


app.get('/security-question', async (req, res) => {
  const { userId } = req.query;

  console.log("Received request for userId:", userId); 

  if (!userId) {
    console.log("No userId provided");
    return res.status(400).json({ error: 'User ID is required' });
  }

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    console.log("Invalid userId format:", userId);
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  try {
    const user = await EmployeeModel.findById(userId, 'securityQuestion securityAnswer role');
    
    if (!user) {
      console.log("User not found for ID:", userId);
      return res.status(404).json({ message: 'User not found' });
    }

    console.log("Found user:", user); 
    res.json({
      securityQuestion: user.securityQuestion || 'No security question set',
      securityAnswer: user.securityAnswer || '',
      role: user.role 
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/update-security-question', async (req, res) => {
  const { userId, newSecurityQuestion, newSecurityAnswer } = req.body;

  if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  if (!newSecurityQuestion || !newSecurityAnswer) {
    return res.status(400).json({ error: 'Question and answer are required' });
  }

  try {
    const user = await EmployeeModel.findById(userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.securityQuestion = newSecurityQuestion;
    user.securityAnswer = newSecurityAnswer;
    await user.save();

    res.json({ 
      success: true,
      message: 'Security question updated successfully'
    });
  } catch (error) {
    console.error('Error updating security question:', error);
    res.status(500).json({ 
      error: 'Server error',
      details: error.message 
    });
  }
});


app.post('/reset-password', async (req, res) => {
  const { name, securityAnswer, newPassword } = req.body;

  if (!name || !securityAnswer || !newPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const user = await EmployeeModel.findOne({ name });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.securityAnswer !== securityAnswer) {
      return res.status(400).json({ message: 'Security answer is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ success: true });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});


app.listen(3001, () => {
  console.log("server is running");
});