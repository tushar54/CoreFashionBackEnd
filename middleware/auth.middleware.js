const jwt = require('jsonwebtoken');
const pool = require('../config/db');

// Verify JWT and identify the user
const authenticateToken = async (req, res, next) => {
  try {
    // Read the Authorization header
    const authHeader = req.headers.authorization;

    // Expected format: Bearer <token>
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({
        message: 'Access denied. Token required.'
      });
    }

    // Verify the token's signature and expiry
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    // Fetch the current user and role from PostgreSQL
    const result = await pool.query(
      `SELECT id, name, email, role
       FROM users
       WHERE id = $1`,
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: 'User no longer exists.'
      });
    }

    // Attach verified user information to the request
    req.user = result.rows[0];

    // Continue to the next middleware or route
    next();
  } catch (error) {
    if (
      error.name === 'JsonWebTokenError' ||
      error.name === 'TokenExpiredError'
    ) {
      return res.status(401).json({
        message: 'Invalid or expired token.'
      });
    }

    console.error('Authentication error:', error);

    return res.status(500).json({
      message: 'Internal server error.'
    });
  }
};

// Check whether the authenticated user has a required role
const authorizeRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: 'Authentication required.'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: 'Forbidden. You do not have permission.'
      });
    }

    next();
  };
};

module.exports = {
  authenticateToken,
  authorizeRole
};
