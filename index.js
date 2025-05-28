require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt"); // For hashing passwords
const EmployeeModel = require("./model/Employee");
const ProductModel = require("./model/Product");
const AssignmentModel = require("./model/Assignment");
const OrderModel = require('./model/Order'); 
const ReportModel = require('./model/Report'); 
const CategoryModel = require("./model/Category");
const BranchModel = require("./model/Branch");
const authenticateToken = require('./model/authenticateToken'); // Import the middleware
const multer = require("multer");
const jwt = require('jsonwebtoken'); // Import the jsonwebtoken library
const jwtSecret = process.env.JWT_SECRET;
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const app = express();


const normalizePhone = (phone) => phone.trim().toLowerCase();
const normalizename = (name) => name.trim().toLowerCase();


app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173',  // your frontend
  credentials: true,                // allow cookies
}));
app.use(bodyParser.json());
// Ensure the "uploads/" directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve static files from the "uploads/" directory
app.use("/uploads", express.static(uploadDir));
// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Use uploadDir here
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`); // Rename the file to avoid conflicts
  },
});

const upload = multer({ storage });

// Middleware to parse JSON
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
  // Check password length
  if (password.length < 6) {
    return "Password must be at least 6 characters long";
  }

  // Check password complexity: at least one letter and one number
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
        callback_url: return_url, // Same as return_url
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
// In your backend (index.js or similar)
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

    // Verify with Chapa API
    const response = await axios.get(
      `https://api.chapa.co/v1/transaction/verify/${tx_ref}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.CHAPA_SECRET_KEY || 'CHASECK_TEST-z8hnOz0YewilQrzs1CSujy2KBoBXR9i6'}`
        },
        timeout: 10000 // 10 second timeout
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
    
    // Determine if the error is from Chapa or our server
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
    // Find the user by name
    const user = await EmployeeModel.findOne({ name });

    if (!user) {
      return res
        .status(404)
        .json({ message: "No record found with this name" });
    }

    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { _id: user._id }, // Payload: Include the user's _id in the token
      process.env.JWT_SECRET, // Secret key for signing the token
      { expiresIn: '1h' } // Token expiration time (e.g., 1 hour)
    );

    // Return the token and user details
    res.json({
      message: "Login successful",
      token, // Include the token in the response
      user: {
        _id: user._id,
        name: user.name,
        role: user.role // Include any other relevant user details
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
    // Validate required fields
    if (!name || !phone || !address || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check for duplicate phone
    const existingUser = await EmployeeModel.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ error: "Duplicate phone" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new customer
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
// Signup route
app.post("/signup", async (req, res) => {
  const { name, phone, password, address } = req.body;

  try {
    // Normalize inputs
    const normalizedPhone = phone.trim().toLowerCase();
    const normalizedName = name.trim().toLowerCase();

    // Validate password
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    // Check if the name is already registered
    const userWithName = await EmployeeModel.findOne({ name: normalizedName });
    if (userWithName) {
      return res.status(400).json({ error: "User with this name is already registered" });
    }

    // Check if the phone number is already registered
    const userWithPhone = await EmployeeModel.findOne({ phone: normalizedPhone });
    if (userWithPhone) {
      return res.status(400).json({ error: "Phone number is already registered" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new EmployeeModel({
      type: "employee",
      role: "user",
      name: normalizedName, // Use the normalized name
      phone: normalizedPhone, // Use the normalized phone number
      password: hashedPassword,
      address,
    });

    // Save the user to the database
    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (err) {
    console.error("Error during signup:", err);
    if (err.code === 11000) {
      // Handle unique constraint violations (shouldn't happen due to checks above)
      res.status(400).json({ error: "Duplicate entry for name or phone number" });
    } else {
      res.status(500).json({ error: "Error signing up" });
    }
  }
});


app.get("/users", async (req, res) => {
  const { type } = req.query; // Optional query parameter

  try {
    let query = {};
    if (type) {
      query.type = type; // Filter by type (employee or customer)
    }

    const users = await EmployeeModel.find(query, "name role phone address");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Error fetching users" });
  }
});



// Delete user endpoint
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
// Update user endpoint
app.put("/users/:id", (req, res) => {
  const { id } = req.params;
  const { role, name, email, password, department } = req.body;

  // Prepare the update object
  const updateFields = { role, name, email, password, department };
  // Use the findByIdAndUpdate method to update the document
  EmployeeModel.findByIdAndUpdate(id, updateFields, { new: true })
    .then((updatedUser) => {
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(updatedUser);
    })
    .catch((err) => {
      if (err.code === 11000) {
        // Handle duplicate key error
        res.status(400).json({ error: "Duplicate id or email" });
      } else {
        res
          .status(500)
          .json({ message: "Error updating user", error: err.message });
      }
    });
});
// Get all employees
app.get("/employees", async (req, res) => {
  try {
    const employees = await EmployeeModel.find({ type: "employee" }, "name role phone address");
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: "Error fetching employees" });
  }
});

// Add a new employee
app.post("/addemployee", async (req, res) => {
  const { role, name, phone, address, password } = req.body;

  // Validate role
  if (!["user", "Admin", "manager", "asset approver"].includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  // Validate password
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    // Check for duplicate name
    const existingEmployee = await EmployeeModel.findOne({ name });
    if (existingEmployee) {
      return res.status(400).json({ error: "Employee is already registered with this name" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new employee
    const newEmployee = new EmployeeModel({
      type: "employee",
      role,
      name,
      phone,
      address,
      password: hashedPassword, // Save hashed password
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

// Delete an employee
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
// Create Branch
app.post("/addbranch", async (req, res) => {
  const { branchName, location, managerId } = req.body;

  try {
    // Validate required fields
    if (!branchName || !location || !managerId) {
      return res.status(400).json({ error: "Branch name, location, and manager are required" });
    }

    // Check for duplicate branch names
    const existingBranch = await BranchModel.findOne({ branchName });
    if (existingBranch) {
      return res.status(400).json({ error: "Branch already exists" });
    }

    // Check if the manager is already assigned to another branch
    const existingManagerAssignment = await BranchModel.findOne({ manager: managerId });
    if (existingManagerAssignment) {
      return res.status(400).json({ error: "This manager is already assigned to another branch" });
    }

    // Create and save the new branch
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
// PUT - Update a branch by ID
app.put("/branches/:id", async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

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

// DELETE - Delete a branch by ID
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

// Assign Branch Manager
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

// Get Branches
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
    // Fetch all stats in parallel
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
       ReportModel.countDocuments(), // Optional: if you have a ReportModel
    ]);

    // Calculate Total Employees as Admins + Managers
    const totalEmployees = totalAdmins + totalManagers;

    // Send back aggregated statistics
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

// /api/user-breakdown
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


// Endpoint to fetch branch manager stats
app.get("/api/branch-manager/:branchManagerId/stats", async (req, res) => {
  try {
    const branchManagerId = req.params.branchManagerId;

    if (!branchManagerId) {
      return res.status(400).json({ error: "branchManagerId is required" });
    }

    const [
      totalProducts,
      totalOrders,
      mostSoldProduct,
      netIncomeAgg,
    ] = await Promise.all([
      ProductModel.countDocuments({ branchManagerId }),

      OrderModel.countDocuments({ branchManagerId }),

      ProductModel.findOne({ branchManagerId }).sort({ quantitySold: -1 }),

      OrderModel.aggregate([
        { $match: { branchManagerId } },
        {
          $group: {
            _id: null,
            netIncome: { $sum: "$totalAmount" },
          },
        },
      ]),
    ]);

    const netIncome = netIncomeAgg[0]?.netIncome || 0;

    const stats = [
      {
        title: "Orders",
        value: totalOrders,
        change: "+0%", // You can calculate real changes later
        color: "blue",
      },
      {
        title: "Total Products",
        value: totalProducts,
        change: "-0%",
        color: "red",
      },
      {
        title: "Most sold product",
        value: mostSoldProduct ? mostSoldProduct.name : "N/A",
        change: "+0%",
        color: "yellow",
      },
      {
        title: "Report",
        value: `ETB ${netIncome}`,
        change: "+0%",
        color: "green",
      },
    ];

    res.json({ stats });

  } catch (err) {
    console.error("Error fetching branch manager stats:", err);
    res.status(500).json({ error: "Failed to fetch branch manager stats" });
  }
});


app.get("/api/branch-manager/sales-breakdown", async (req, res) => {
  try {
    const branchManagerId = req.user._id;

    // Fetch sales breakdown by category
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

    // Aggregate net income by month
    const netIncome = await OrderModel.aggregate([
      {
        $match: { branchManagerId },
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } }, // Group by month
          earnings: { $sum: "$totalAmount" }, // Sum of all order amounts
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

app.get("/api/branch-manager/earning-by-location", async (req, res) => {
  try {
    const branchManagerId = req.user._id;

    // Aggregate earnings by location
    const earningsByLocation = await OrderModel.aggregate([
      {
        $match: { branchManagerId },
      },
      {
        $group: {
          _id: "$location", // Assuming each order has a `location` field
          totalEarnings: { $sum: "$totalAmount" },
        },
      },
      {
        $project: {
          country: "$_id",
          value: "$totalEarnings",
          _id: 0,
        },
      },
    ]);

    res.json(earningsByLocation);
  } catch (err) {
    console.error("Error fetching earnings by location:", err);
    res.status(500).json({ error: "Failed to fetch earnings by location" });
  }
});
app.get("/api/branch-manager/recent-activity", async (req, res) => {
  try {
    const branchManagerId = req.user._id;

    // Fetch recent activity (e.g., orders or updates)
    const recentActivity = await ActivityModel.find({ branchManagerId })
      .sort({ createdAt: -1 }) // Sort by most recent
      .limit(5); // Limit to 5 recent activities

    res.json(recentActivity);
  } catch (err) {
    console.error("Error fetching recent activity:", err);
    res.status(500).json({ error: "Failed to fetch recent activity" });
  }
});

// Route to register a category
app.post('/category', async (req, res) => {
  try {
    const { code, description, category, branchManagerId } = req.body;

    // Validate branchManagerId
    if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
      return res.status(400).json({ error: 'Invalid or missing branch manager ID.' });
    }

    // Create a new category document
    const newCategory = new CategoryModel({
      code,
      description,
      category,
      branchManagerId, // Associate the category with the branch manager
    });

    // Save the category to the database
    await newCategory.save();

    res.status(201).json({ message: 'Category registered successfully.' });
  } catch (error) {
    console.error('Error registering category:', error); // Log the error for debugging
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to fetch all categories
app.get('/categories', async (req, res) => {
  try {
    const { branchManagerId } = req.query;

    // Validate branchManagerId
    if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
      return res.status(400).json({ error: 'Invalid or missing branch manager ID.' });
    }

    // Fetch categories for the specified branch manager
    const categories = await CategoryModel.find({ branchManagerId });

    res.status(200).json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Register Product Route
app.post("/addproduct", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { name, purchaseprice, saleprice, description, category } = req.body;

    // Extract branchManagerId from the authenticated user
    const branchManagerId = req.user._id;

    // Check if a file was uploaded
    if (!req.file) {
      return res.status(400).json({ message: "Image is required." });
    }

    // Generate a relative path for the image
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
      branchManagerId, // Include the branchManagerId here
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

    if (!productId || !quantity || !supplier) {
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

    // Update the product's stock quantity
    product.quantity += parsedQuantity;
    await product.save();

    res.status(201).json({ message: "Stock purchase recorded successfully.", product });
  } catch (error) {
    console.error("Error recording stock purchase:", error);
    res.status(400).json({ error: error.message });
  }
});

// Endpoint to get all products, aggregated by category and filtered by branch manager
app.get("/productlist", async (req, res) => {
  const { search, branchManagerId } = req.query;

  // Validate branchManagerId
  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    console.error("Invalid or missing branch manager ID:", branchManagerId);
    return res.status(400).json({ message: "Invalid or missing branch manager ID." });
  }

  try {
    // Convert branchManagerId to ObjectId
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
              image: "$image", // Include the image path
            }
          }
        }
      }
    ]);

    // Precompute stock alerts
    const stockAlerts = products.flatMap(group =>
      group.products.filter(product => product.status === "Low Stock" || product.status === "Out Of Stock")
    );

    res.json({
      products,
      stockAlerts: stockAlerts.length > 0 ? stockAlerts : null // Include stock alerts in the response
    });
  } catch (err) {
    console.error("Error fetching products:", err); // Log the error
    res.status(500).json({ message: "Error fetching products." });
  }
});

// Update product information
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
      category // Ensure category is included if needed
    } = req.body;

    // Find and update the product
    const updatedProduct = await ProductModel.findByIdAndUpdate(
      id,
      {
        name,
        productno,
        purchaseprice,
        saleprice,
        quantity,
        description,
        status, // Update status based on quantity
        category // Include category in the update if needed
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

// DELETE product  by ID
app.delete('/deleteproduct/:id', async (req, res) => {
  try {
    const productId = req.params.id;

    // Check if the product  exists before deleting
    const product = await ProductModel.findById(productId);

    if (!product ) {
      return res.status(404).json({ message: 'Product  not found' });
    }

    // Delete the product 
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

    // Calculate cost price
    const costPrice = product.purchaseprice * quantity;

    // Decrement asset quantity
    product.quantity -= quantity;

    // Update product status based on remaining quantity
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

// Endpoint to get all sold products
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

// In your backend route (e.g., routes/reports.js)
app.post('/reports', async (req, res) => {
  const { startDate, endDate, branchManagerId } = req.body;

  if (!startDate || !endDate || !branchManagerId) {
    return res.status(400).json({ error: 'Start date, end date, and branch manager ID are required' });
  }

  const start = new Date(startDate);
  const end = new Date(endDate);
  end.setHours(23, 59, 59, 999);

  try {
    const orders = await OrderModel.find({
      dateOrdered: { $gte: start, $lte: end },
      branchManagerId: branchManagerId,
      status: "Confirmed",
    }).populate({
      path: 'product',
      select: 'name purchaseprice saleprice quantity status'
    });

    const assignments = await AssignmentModel.find({
      dateAssigned: { $gte: start, $lte: end },
      branchManagerId: branchManagerId,
    }).populate({
      path: 'product',
      select: 'name purchaseprice saleprice quantity status'
    });
    // Calculate totals
    const totalSalesFromOrders = orders.reduce((sum, order) => sum + (order.totalPrice || 0), 0);
    const costPriceFromOrders = orders.reduce(
      (sum, order) => sum + ((order.product?.purchaseprice || 0) * (order.quantity || 0)),
      0
    );

    const totalSalesFromAssignments = assignments.reduce(
      (sum, assignment) => sum + (assignment.totalPrice || 0),
      0
    );
    const costPriceFromAssignments = assignments.reduce(
      (sum, assignment) => sum + ((assignment.product?.purchaseprice || 0) * (assignment.quantity || 0)),
      0
    );

    const totalSales = totalSalesFromOrders + totalSalesFromAssignments;
    const costPrice = costPriceFromOrders + costPriceFromAssignments;
    const profitOrLoss = totalSales - costPrice;

    // Create detailed report data
    // In your POST /reports route
    const reportData = [
      ...orders.map(order => ({
        product: order.product?._id,
        name: order.product?.name || 'Unknown Product',
        type: "Order", // Explicitly set type for orders
        quantity: Number(order.quantity) || 0,
        purchasePrice: Number(order.product?.purchaseprice) || 0,
        salePrice: Number(order.product?.saleprice) || 0,
        totalPrice: Number(order.totalPrice) || 0,
        date: order.dateOrdered ? new Date(order.dateOrdered) : new Date(), // Ensure proper Date object
        stockLevel: Number(order.product?.quantity) || 0,
        status: order.product?.status || 'Available'
      })),
      ...assignments.map(assignment => ({
        product: assignment.product?._id,
        name: assignment.product?.name || 'Unknown Product',
        type: "Sale", // Explicitly set type for assignments
        quantity: Number(assignment.quantity) || 0,
        purchasePrice: Number(assignment.product?.purchaseprice) || 0,
        salePrice: Number(assignment.totalPrice) / Number(assignment.quantity) || 0,
        totalPrice: Number(assignment.totalPrice) || 0,
        date: assignment.dateAssigned ? new Date(assignment.dateAssigned) : new Date(), // Ensure proper Date object
        stockLevel: Number(assignment.product?.quantity) || 0,
        status: assignment.product?.status || 'Available'
      }))
    ];
    
    // Debug output to verify all fields
    console.log("Date verification:", {
      orderDate: orders[0]?.dateOrdered,
      assignmentDate: assignments[0]?.dateAssigned,
      reportDataDate: reportData[0]?.date,
      isDate: reportData[0]?.date instanceof Date
    });

    const report = new ReportModel({
      startDate,
      endDate,
      totalSales,
      profitOrLoss,
      reportData,
      branchManagerId,
    });


    await report.save();
    res.status(201).json(report);
  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({ error: "Error generating report", details: error.message });
  }
});

// Endpoint to get all reports
app.get('/reports', async (req, res) => {
  const { branchManagerId } = req.query;

  if (!branchManagerId) {
    return res.status(400).json({ error: 'Branch manager ID is required' });
  }

  try {
    const reports = await ReportModel.find({ branchManagerId })
      .sort({ createdAt: -1 })
      .lean(); // Use lean() for better performance
    
    // Ensure dates are properly formatted
    const formattedReports = reports.map(report => ({
      ...report,
      reportData: report.reportData.map(item => ({
        ...item,
        date: item.date ? new Date(item.date).toISOString() : null,
        // For frontend display, you might want to add:
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
// Get only reports that have been sent to admin
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

// Endpoint for branch managers to send reports to admin
// Update the send-to-admin endpoint
app.post('/reports/:id/send-to-admin', async (req, res) => {
  try {
    const report = await ReportModel.findByIdAndUpdate(
      req.params.id,
      { 
        sentToAdmin: true,
        sentAt: new Date(),
        status: 'submitted' // If you're using status tracking
      },
      { new: true }
    ).populate('branchManagerId', 'name email');
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Optional: Send notification to admin
    // notificationService.notifyAdmin(report);

    res.json({ 
      success: true,
      report 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Add to your admin API
app.post('/admin/reports/:id/comment', async (req, res) => {
  const { comment } = req.body;
  await ReportModel.findByIdAndUpdate(
    req.params.id,
    { adminNotes: comment }
  );
  res.json({ success: true });
});


// Endpoint to create an order
app.post('/orders', async (req, res) => {
  try {
    const { product, quantity, totalPrice, userId, branchManagerId, branchId, tx_ref } = req.body;

    // Validate all required fields
    const requiredFields = ['product', 'quantity', 'totalPrice', 'userId', 'branchManagerId', 'branchId', 'tx_ref'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        error: "Missing required fields",
        missingFields
      });
    }

    // More comprehensive duplicate check
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

    // Create the order with additional validation
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

    // Populate and return the order
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
// Endpoint to get all orders
app.get("/orders", (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  // Fetch orders belonging to the logged-in user
  OrderModel.find({ userId: userId })
    .populate('product') // Populate product details
    .populate('userId', 'name address phone') // Populate user details: name, address, and phone
    .then(orders => {
      res.json(orders);
    })
    .catch(err => {
      res.status(500).json({ error: "Error fetching orders", message: err.message });
    });
});

// Get all orders for a branch manager
// GET /admin/orders
app.get("/admin/orders", async (req, res) => {
  const { branchManagerId } = req.query;

  if (!branchManagerId || !mongoose.Types.ObjectId.isValid(branchManagerId)) {
    return res.status(400).json({ error: "Invalid or missing branch manager ID" });
  }

  try {
    // Find all branches managed by the branch manager
    const branches = await BranchModel.find({ manager: branchManagerId });

    // Extract branch IDs
    const branchIds = branches.map(branch => branch._id);

    if (branchIds.length === 0) {
      return res.status(404).json({ error: "No branches found for this branch manager" });
    }

    // Find all orders where the branchId matches one of the branch manager's branches
    const orders = await OrderModel.find({ branchId: { $in: branchIds } })
      .populate("userId", "name address phone")
      .populate("product");

    // Return an empty array if no orders are found
    if (orders.length === 0) {
      return res.status(200).json([]); // Return an empty array with a 200 status
    }

    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Error fetching orders", details: error.message });
  }
});

// Confirm an order
app.patch('/admin/orders/:orderId/confirm', async (req, res) => {
  try {
    const { orderId } = req.params;

    // Find the order and populate the product details
    const order = await OrderModel.findById(orderId).populate('product');
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (!order.product) {
      return res.status(400).json({ error: "Product not found for this order" });
    }

    // Check if there is sufficient stock
    if (order.product.quantity < order.quantity) {
      return res.status(400).json({ error: "Insufficient stock" });
    }

    // Reduce the product stock
    order.product.quantity -= order.quantity;
    order.product.status =
      order.product.quantity === 0
        ? 'Out Of Stock'
        : order.product.quantity < 5
        ? 'Low Stock'
        : 'Available';

    // Save the updated product
    await order.product.save();

    // Confirm the order
    order.status = 'Confirmed';
    await order.save();

    // Fetch the updated order with populated fields
    const updatedOrder = await OrderModel.findById(order._id).populate('userId product');

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error confirming order:", error.message, error.stack);
    res.status(500).json({ error: "Error confirming order", details: error.message });
  }
});

app.patch('/admin/orders/:orderId/reject', async (req, res) => {
  try {
    const { orderId } = req.params;

    // Find the order and populate the product details
    const order = await OrderModel.findById(orderId).populate('product');
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    // If the order was confirmed, restore the product stock
    if (order.status === 'Confirmed') {
      order.product.quantity += order.quantity;
      order.product.status =
        order.product.quantity === 0
          ? 'Out Of Stock'
          : order.product.quantity < 5
          ? 'Low Stock'
          : 'Available';

      // Save the updated product
      await order.product.save();
    }

    // Update the order status to "Rejected"
    order.status = 'Rejected';
    await order.save();

    // Fetch the updated order with populated fields
    const updatedOrder = await OrderModel.findById(order._id).populate('userId product');

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error rejecting order:", error);
    res.status(500).json({ error: "Error rejecting order", details: error.message });
  }
});

// In your Express server (e.g., index.js or server.js)
app.get('/current_user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  res.json(req.session.user); // Includes _id, role, etc.
});

// Endpoint to reset password
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
    const user = await EmployeeModel.findOne({ name: name }); // Searching by name now

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password
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

// Route to get the security question for a user by email
app.get('/security-question', async (req, res) => {
  const { userId } = req.query; // Get the userId from query parameters

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  try {
    const user = await EmployeeModel.findById(userId).select('securityQuestion securityAnswer');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      securityQuestion: user.securityQuestion || 'No current security question',
      securityAnswer: user.securityAnswer || ''
    });
  } catch (error) {
    console.error('Error fetching security question:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.post('/update-security-question', async (req, res) => {
  const { userId, newSecurityQuestion, newSecurityAnswer } = req.body;

  try {
    const user = await EmployeeModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.securityQuestion = newSecurityQuestion;
    user.securityAnswer = newSecurityAnswer;
    await user.save();

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating security question:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Route to reset the password
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