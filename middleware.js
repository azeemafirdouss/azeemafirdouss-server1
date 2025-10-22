// middleware.js
const jwt = require("jsonwebtoken");
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];

  // Debugging logs - will help explain 401/403/404 issues
  console.log('DEBUG authHeader:', authHeader ? '[present]' : '[missing]');
  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('DEBUG token verify error:', err.message);
      return res.status(403).json({ error: "Invalid token." });
    }
    console.log('DEBUG decoded token user:', user);
    req.user = user;
    next();
  });
}

module.exports = { authenticateToken };
