const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');
const { authenticateToken, authenticateExtension } = require('../middleware/auth');

// Receive email analysis from extension
router.post('/analyze', authenticateExtension, analysisController.analyzeEmail);

// Get all reports
router.get('/reports', authenticateToken, analysisController.getAllReports);

// Get a report by ID
router.get('/reports/:id', authenticateToken, analysisController.getReportById);

// Delete a report by ID
router.delete('/reports/:id', authenticateToken, analysisController.deleteReport);

// Get dashboard stats
router.get('/stats/dashboard', authenticateToken, analysisController.getDashboardStats);

// Get global stats
router.get('/stats/global', authenticateToken, analysisController.getGlobalStats);

module.exports = router;