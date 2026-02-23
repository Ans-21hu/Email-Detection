const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    emailContent: {
        type: String,
        required: true
    },
    sender: {
        type: String,
        required: true
    },
    recipient: {
        type: String,
        required: true
    },
    subject: {
        type: String,
        required: true
    },
    riskScore: {
        type: Number,
        required: true,
        min: 0,
        max: 100
    },
    riskLevel: {
        type: String,
        enum: ['low', 'medium', 'high'],
        default: 'low'
    },
    threats: [{
        type: String
    }],
    recommendations: [{
        type: String
    }],
    attachments: [{
        name: String,
        type: String,
        size: Number
    }],
    status: {
        type: String,
        enum: ['pending', 'analyzed', 'malicious', 'safe'],
        default: 'pending'
    },
    analysisResult: {
        type: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Report', reportSchema);