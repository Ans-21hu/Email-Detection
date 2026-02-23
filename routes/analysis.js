const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');
const authController = require('../controllers/authController');

// Receive email analysis from extension
router.post('/analyze', analysisController.receiveAnalysis);

// Get all reports
router.get('/reports', authController.authMiddleware, analysisController.getAllReports);

// Get a report by ID
router.get('/reports/:id', authController.authMiddleware, analysisController.getReportById);

// Delete a report by ID
router.delete('/reports/:id', authController.authMiddleware, analysisController.deleteReport);

// Get dashboard stats
router.get('/stats/dashboard', authController.authMiddleware, analysisController.getDashboardStats);

// Get global stats
router.get('/stats/global', authController.authMiddleware, analysisController.getGlobalStats);

module.exports = router;