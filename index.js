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
const multer = require("multer");
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
const uploadDir = path.join(__dirname, "uploads"); // Define uploadDir here
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve static files from the "uploads/" directory
app.use("/uploads", express.static(uploadDir)); // Use uploadDir after it's defined

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
        callback_url: return_url,
      },
      {
        headers: {
          Authorization: 'Bearer CHASECK_TEST-z8hnOz0YewilQrzs1CSujy2KBoBXR9i6',
        },
      }
    );

    res.status(200).json({ checkout_url: response.data.data.checkout_url });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to initialize payment' });
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
    const user = await EmployeeModel.findOne({ name: name});

    if (!user) {
      return res
        .status(404)
        .json({ message: "No record found with this name" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      res.json(["good", user]);
    } else {
      res.status(401).json({ message: "Incorrect password" });
    }
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
app.post("/addproduct", upload.single("image"), async (req, res) => {
  try {
    const { name, purchaseprice, saleprice, description, category } = req.body;
    const imagePath = req.file ? req.file.path : null;

    if (!name || !purchaseprice || !saleprice || !category) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const purchasePrice = parseFloat(purchaseprice);
    const salePrice = parseFloat(saleprice);

    if (isNaN(purchasePrice) || isNaN(salePrice)) {
      return res.status(400).json({ error: "Invalid prices." });
    }

    const categoryExists = await CategoryModel.findById(category);
    if (!categoryExists) {
      return res.status(400).json({ error: "Category not found." });
    }

    const newProduct = new ProductModel({
      name,
      purchaseprice: purchasePrice,
      saleprice: salePrice,
      description,
      category: categoryExists._id,
      image: imagePath,
    });

    await newProduct.save();
    res.status(201).json({ message: "Product added successfully.", product: newProduct });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(400).json({ error: error.message });
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
    }).populate('product', 'name purchaseprice saleprice quantity status');

    const assignments = await AssignmentModel.find({
      dateAssigned: { $gte: start, $lte: end },
      branchManagerId: branchManagerId,
    }).populate('product', 'name purchaseprice quantity status');

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

    const reportData = [
      ...orders.map(order => ({
        productName: order.product.name,
        quantity: order.quantity,
        totalPrice: order.totalPrice,
        date: order.dateOrdered,
        stockLevel: order.product.quantity,
        status: order.product.status,
        source: "Order",
      })),
      ...assignments.map(assignment => ({
        productName: assignment.product.name,
        quantity: assignment.quantity,
        totalPrice: assignment.totalPrice,
        date: assignment.dateAssigned,
        stockLevel: assignment.product.quantity,
        status: assignment.product.status,
        source: "Sold Product",
      })),
    ];

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
      .exec();

    res.json(reports);
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ error: "Error fetching reports" });
  }
});

// Endpoint to create an order
app.post('/orders', async (req, res) => {
  const { product, quantity, totalPrice, userId, branchManagerId, branchId } = req.body;

  if (!product || !quantity || !totalPrice || !userId || !branchManagerId || !branchId) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (
    !mongoose.Types.ObjectId.isValid(product) ||
    !mongoose.Types.ObjectId.isValid(userId) ||
    !mongoose.Types.ObjectId.isValid(branchManagerId) ||
    !mongoose.Types.ObjectId.isValid(branchId)
  ) {
    return res.status(400).json({ error: "Invalid Product ID, User ID, Branch Manager ID, or Branch ID" });
  }

  try {
    const productDoc = await ProductModel.findById(product);
    if (!productDoc) {
      return res.status(404).json({ error: "Product not found" });
    }

    const userDoc = await EmployeeModel.findById(userId);
    if (!userDoc) {
      return res.status(404).json({ error: "User not found" });
    }

    const branchManagerDoc = await EmployeeModel.findById(branchManagerId);
    if (!branchManagerDoc) {
      return res.status(404).json({ error: "Branch manager not found" });
    }

    const branchDoc = await BranchModel.findById(branchId);
    if (!branchDoc) {
      return res.status(404).json({ error: "Branch not found" });
    }

    if (productDoc.quantity < quantity) {
      return res.status(400).json({ error: "Insufficient stock", remainingStock: productDoc.quantity });
    }

    const order = new OrderModel({
      product,
      quantity,
      totalPrice,
      userId,
      branchId,
      branchManagerId,
      dateOrdered: new Date(),
      status: 'Pending'
    });

    await order.save();


    const populatedOrder = await OrderModel.findById(order._id)
      .populate('product')
      .populate('branchId')
      .populate('branchManagerId');

    res.json(populatedOrder);
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ error: "Error creating order", details: error.message });
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