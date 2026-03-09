const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Helper to get JWT Secret
const getJwtSecret = () => process.env.JWT_SECRET || 'MailXpose_Secret_789_Security_Key';

// User authentication middleware (Web)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, getJwtSecret(), (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        req.user = user;
        next();
    });
};

// Extension authentication middleware
const authenticateExtension = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Extension token required'
        });
    }

    try {
        const decoded = jwt.verify(token, getJwtSecret());

        // Dynamic requiring to avoid circular dependencies if needed
        const ExtensionInstall = mongoose.model('ExtensionInstall');
        const User = mongoose.model('User');

        const extension = await ExtensionInstall.findOne({
            extensionId: decoded.extensionId,
            userId: decoded.userId,
            isActive: true
        });

        if (!extension) {
            return res.status(403).json({
                success: false,
                message: 'Extension not found or inactive'
            });
        }

        req.user = { id: extension.userId };
        req.extension = extension;
        next();
    } catch (err) {
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired extension token'
        });
    }
};

module.exports = {
    authenticateToken,
    authenticateExtension
};
