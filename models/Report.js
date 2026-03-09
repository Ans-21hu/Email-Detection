const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    subject: {
        type: String,
        required: true,
        trim: true
    },
    sender: {
        type: String,
        required: true,
        trim: true
    },
    recipient: {
        type: String,
        trim: true
    },
    content: {
        type: String
    },
    emailContent: String, // Keeping for backward compatibility
    riskLevel: {
        type: String,
        enum: ['low', 'medium', 'high'],
        default: 'low'
    },
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    status: {
        type: String,
        enum: ['safe', 'suspicious', 'malicious'],
        default: 'safe'
    },
    threats: [{
        type: String
    }],
    analysisDate: {
        type: Date,
        default: Date.now
    },
    details: {
        type: Object
    },
    analysisTime: {
        type: Number, // milliseconds
        default: 0
    },
    source: {
        type: String,
        enum: ['web', 'extension', 'api'],
        default: 'web'
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Report', reportSchema);