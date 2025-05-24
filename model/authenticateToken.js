const jwt = require('jsonwebtoken');

// Middleware to authenticate requests
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from "Bearer <token>"
  
    if (!token) {
      return res.status(401).json({ message: "Access denied. No token provided." });
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token
      req.user = decoded; // Attach the decoded user object to the request
      next(); // Proceed to the next middleware/route handler
    } catch (err) {
      res.status(403).json({ message: "Invalid or expired token." });
    }
  };
module.exports = authenticateToken;