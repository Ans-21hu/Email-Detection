const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    fullName: {
        type: String,
        trim: true
    },
    firstName: String, // Keeping for backward compatibility if needed
    lastName: String,  // Keeping for backward compatibility if needed
    phoneNumber: {
        type: String,
        trim: true
    },
    subscriptionPlan: {
        type: String,
        default: 'free',
        enum: ['free', 'pro', 'enterprise', 'elite']
    },
    subscriptionStatus: {
        type: String,
        default: 'active',
        enum: ['active', 'expired', 'canceled']
    },
    subscriptionStartDate: Date,
    subscriptionEndDate: Date,
    apiKey: {
        type: String,
        unique: true
    },
    totalScans: {
        type: Number,
        default: 0
    },
    preferences: {
        darkMode: { type: Boolean, default: true },
        autoScan: { type: Boolean, default: true },
        detailedReports: { type: Boolean, default: true },
        emailNotifications: { type: Boolean, default: true },
        loginAlerts: { type: Boolean, default: true },
        weeklyDigest: { type: Boolean, default: false },
        twoFactorAuth: { type: Boolean, default: false }
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: Date,
    lastPasswordChange: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Auto-generate username if not provided
userSchema.pre('save', function (next) {
    if (!this.username) {
        this.username = `${this.firstName.toLowerCase()}${this.lastName.toLowerCase()}${Date.now().toString().slice(-4)}`;
    }
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);