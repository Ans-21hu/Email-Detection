const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Register new user
router.post('/register', authController.register);

// Login user
router.post('/login', authController.login);

// Verify token
router.get('/verify', authController.verifyToken);

// Get user profile (protected)
router.get('/profile', authController.authMiddleware, authController.getProfile);

module.exports = router;