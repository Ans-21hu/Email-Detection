const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Generate JWT token
exports.generateToken = (user) => {
    return jwt.sign(
        {
            id: user._id,
            email: user.email,
            name: `${user.firstName} ${user.lastName}`,
            role: user.role || 'user'
        },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Authentication middleware
exports.authMiddleware = (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                error: 'Access denied. No token provided.'
            });
        }

        // Check if token starts with 'Bearer '
        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token format. Use: Bearer <token>'
            });
        }

        // Extract token
        const token = authHeader.split(' ')[1];

        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Add user info to request
        req.user = decoded;
        next();
    } catch (error) {
        console.error(error);
        res.status(401).json({
            success: false,
            error: 'Invalid or expired token'
        });
    }
};

// User registration
exports.register = async (req, res) => {
    try {
        console.log('='.repeat(60));
        console.log('🚀 REGISTRATION REQUEST RECEIVED');
        console.log('📦 Request body:', req.body);

        const { firstName, lastName, email, password, username } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            console.log('❌ Missing required fields');
            return res.status(400).json({
                success: false,
                message: 'All required fields must be filled'
            });
        }

        // Generate username if not provided
        const finalUsername = username || `${firstName.toLowerCase()}${lastName.toLowerCase()}${Date.now().toString().slice(-4)}`;

        console.log('🔍 Checking for existing user...');

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email: email.toLowerCase() },
                { username: finalUsername }
            ]
        });

        if (existingUser) {
            console.log('❌ User already exists:', existingUser.email);
            return res.status(400).json({
                success: false,
                message: existingUser.email === email.toLowerCase()
                    ? 'User with this email already exists'
                    : 'Username already taken'
            });
        }

        console.log('💾 Creating new user...');

        // Create new user
        const newUser = new User({
            firstName,
            lastName,
            fullName: `${firstName} ${lastName}`,
            email: email.toLowerCase(),
            password,
            username: finalUsername
        });

        console.log('💾 Saving user to database...');

        // Save user
        const savedUser = await newUser.save();

        console.log('✅ User saved successfully!');
        console.log('✅ User ID:', savedUser._id);
        console.log('✅ Email:', savedUser.email);
        console.log('✅ Username:', savedUser.username);

        // Generate token
        console.log('🔐 Generating JWT token...');
        const token = jwt.sign(
            {
                id: savedUser._id,
                email: savedUser.email,
                name: `${savedUser.firstName} ${savedUser.lastName}`
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log('🎉 REGISTRATION COMPLETED SUCCESSFULLY');
        console.log('='.repeat(60));

        res.status(201).json({
            success: true,
            message: 'Registration successful!',
            token,
            user: {
                id: savedUser._id,
                firstName: savedUser.firstName,
                lastName: savedUser.lastName,
                fullName: `${savedUser.firstName} ${savedUser.lastName}`,
                email: savedUser.email,
                username: savedUser.username,
                subscriptionPlan: savedUser.subscriptionPlan,
                trialEndDate: savedUser.trialEndDate
            }
        });

    } catch (error) {
        console.error('='.repeat(60));
        console.error('💥 REGISTRATION ERROR');
        console.error('❌ Error name:', error.name);
        console.error('❌ Error message:', error.message);
        console.error('❌ Error code:', error.code);

        if (error.name === 'ValidationError') {
            console.error('❌ Validation errors:', error.errors);
        }

        if (error.code === 11000) {
            console.error('❌ Duplicate key error:', error.keyValue);
            return res.status(400).json({
                success: false,
                message: 'Email or username already exists'
            });
        }

        console.error('='.repeat(60));

        res.status(500).json({
            success: false,
            message: 'Server error during registration',
            error: error.message
        });
    }
};

// User login
exports.login = async (req, res) => {
    try {
        console.log('🔑 LOGIN ATTEMPT');

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            console.log('❌ User not found:', email);
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            console.log('❌ Invalid password for:', email);
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate token
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email,
                name: `${user.firstName} ${user.lastName}`
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log('✅ LOGIN SUCCESSFUL:', email);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                fullName: `${user.firstName} ${user.lastName}`,
                email: user.email,
                username: user.username,
                subscriptionPlan: user.subscriptionPlan,
                trialEndDate: user.trialEndDate,
                lastLogin: user.lastLogin
            }
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login',
            error: error.message
        });
    }
};

// Verify token
exports.verifyToken = (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                error: 'No token provided'
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        return res.json({
            success: true,
            user: decoded
        });

    } catch (error) {
        return res.status(401).json({
            success: false,
            error: 'Invalid or expired token'
        });
    }
};

// Get user profile
exports.getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            user: user
        });

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};