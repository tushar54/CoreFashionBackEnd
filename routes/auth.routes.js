
const express = require('express');
const {
  authenticateToken,
  authorizeRole
} = require('../middleware/auth.middleware');

const {
  registerUser,
  loginUser
} = require('../controllers/auth.controller');

const router = express.Router();

// POST /api/auth/register
router.post('/register', registerUser);

// POST /api/auth/login
router.post('/login', loginUser);
// GET /api/auth/me
router.get('/me', authenticateToken, (req, res) => {
  res.json({
    message: 'Token verified successfully',
    user: req.user
  });
});
router.get(
  '/admin-test',
  authenticateToken,
  authorizeRole('admin'),
  (req, res) => {
    res.json({
      message: 'Welcome, admin!',
      user: req.user
    });
  }
);

module.exports = router;
