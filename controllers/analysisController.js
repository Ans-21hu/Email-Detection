const mongoose = require('mongoose');
const Report = require('../models/Report');
const User = require('../models/User');

// Helper function for email analysis (Sync with server.js)
function analyzeEmail(content, sender, subject, headers = {}) {
    // Initialize analysis result
    let riskScore = 0;
    const threats = [];
    const details = {
        analysisTime: Date.now(),
        confidence: 0,
        indicators: [],
        senderAnalysis: {},
        contentAnalysis: {},
        headerAnalysis: headers || {}
    };

    // Check for suspicious keywords
    const suspiciousKeywords = [
        'password', 'urgent', 'immediately', 'click here', 'verify', 'account',
        'suspended', 'locked', 'security', 'login', 'confirm', 'update',
        'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google'
    ];

    const maliciousKeywords = [
        'wire transfer', 'bitcoin', 'crypto', 'phishing', 'virus', 'malware',
        'ransomware', 'trojan', 'exploit', 'hack', 'breach', 'compromised'
    ];

    let foundSuspicious = 0;
    let foundMalicious = 0;

    const contentLower = content.toLowerCase();
    const subjectLower = subject.toLowerCase();
    const senderLower = sender.toLowerCase();

    // Analyze sender
    const senderDomain = senderLower.split('@')[1];
    const suspiciousDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const trustedDomains = ['company.com', 'organization.org', 'edu.in'];

    details.senderAnalysis.domain = senderDomain;
    details.senderAnalysis.isSuspiciousDomain = suspiciousDomains.includes(senderDomain);
    details.senderAnalysis.isTrustedDomain = trustedDomains.includes(senderDomain);

    // Header Verification (SPF/DKIM)
    if (headers && (headers.spf || headers.dkim)) {
        if (headers.spf) {
            const spfDomain = headers.spf.toLowerCase();
            if (spfDomain !== senderDomain && !senderDomain.endsWith('.' + spfDomain)) {
                riskScore += 25;
                threats.push('spf_mismatch');
                details.indicators.push(`SPF Mismatch: mailed-by ${headers.spf} doesn't match ${senderDomain}`);
            } else {
                riskScore -= 5;
                details.indicators.push('SPF Verification: Passed');
            }
        }
        if (headers.dkim) {
            details.indicators.push(`DKIM Signed by: ${headers.dkim}`);
            riskScore -= 5;
        } else {
            riskScore += 15;
            threats.push('dkim_missing');
            details.indicators.push('Security Warning: Missing DKIM signature');
        }
    }

    if (suspiciousDomains.includes(senderDomain)) {
        riskScore += 10;
        details.indicators.push(`Suspicious sender domain: ${senderDomain}`);
    }

    if (trustedDomains.includes(senderDomain)) {
        riskScore -= 5; // Bonus for trusted domains
    }

    // Check for urgency in subject
    if (subjectLower.includes('urgent') || subjectLower.includes('immediate')) {
        riskScore += 20;
        threats.push('urgency_tactic');
        details.indicators.push('Urgency tactics detected in subject');
        details.contentAnalysis.hasUrgency = true;
    }

    // Check keywords in content
    suspiciousKeywords.forEach(keyword => {
        if (contentLower.includes(keyword) || subjectLower.includes(keyword)) {
            foundSuspicious++;
            threats.push(`suspicious_keyword_${keyword}`);
            details.indicators.push(`Found suspicious keyword: ${keyword}`);
        }
    });

    maliciousKeywords.forEach(keyword => {
        if (contentLower.includes(keyword) || subjectLower.includes(keyword)) {
            foundMalicious++;
            threats.push(`malicious_keyword_${keyword}`);
            details.indicators.push(`Found malicious keyword: ${keyword}`);
        }
    });

    // Check for links
    const linkRegex = /https?:\/\/[^\s]+/g;
    const links = content.match(linkRegex) || [];
    details.contentAnalysis.linkCount = links.length;

    if (links.length > 0) {
        riskScore += links.length * 5;
        threats.push('contains_links');
        details.indicators.push(`Found ${links.length} links in email`);
    }

    // Check for suspicious links
    const suspiciousLinks = links.filter(link =>
        link.includes('bit.ly') ||
        link.includes('tinyurl') ||
        link.includes('shortener')
    );

    if (suspiciousLinks.length > 0) {
        riskScore += 15;
        threats.push('suspicious_shortened_links');
        details.indicators.push(`Found ${suspiciousLinks.length} shortened/suspicious links`);
    }

    // Check for attachments
    const attachmentRegex = /\.(exe|zip|rar|js|bat|cmd|scr|pif|vb|vbs|wsf|wsh|msi|docm|xlsm|pptm)/gi;
    const hasSuspiciousAttachment = attachmentRegex.test(content);
    details.contentAnalysis.hasSuspiciousAttachment = hasSuspiciousAttachment;

    if (hasSuspiciousAttachment) {
        riskScore += 30;
        threats.push('suspicious_attachment');
        details.indicators.push('Suspicious attachment detected');
    }

    // Check email format
    const hasPoorFormatting = (content.match(/\n/g) || []).length < 3 && content.length > 200;
    details.contentAnalysis.hasPoorFormatting = hasPoorFormatting;

    if (hasPoorFormatting) {
        riskScore += 5;
        details.indicators.push('Poor email formatting detected');
    }

    // Add scores from keywords
    riskScore += foundSuspicious * 5;
    riskScore += foundMalicious * 15;

    // Cap risk score at 100
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    // Determine risk level and status
    let riskLevel = 'low';
    let status = 'safe';

    if (riskScore >= 70) {
        riskLevel = 'high';
        status = 'malicious';
    } else if (riskScore >= 40) {
        riskLevel = 'medium';
        status = 'suspicious';
    }

    return {
        riskScore,
        riskLevel,
        status,
        threats,
        details,
        analysisDate: new Date()
    };
}

exports.analyzeEmail = async (req, res) => {
    try {
        const { subject, sender, content, recipient, headers } = req.body;
        const userId = req.user.id;

        if (!subject || !sender) {
            return res.status(400).json({
                success: false,
                message: 'Subject and sender are required'
            });
        }

        const startTime = Date.now();
        const analysisResult = analyzeEmail(content || '', sender, subject, headers || {});
        const analysisTime = Date.now() - startTime;

        const newReport = new Report({
            userId,
            subject: subject.trim(),
            sender: sender.trim(),
            recipient: recipient || sender.trim(),
            content: content || '',
            riskLevel: analysisResult.riskLevel,
            riskScore: analysisResult.riskScore,
            status: analysisResult.status,
            threats: analysisResult.threats,
            details: analysisResult.details,
            analysisTime,
            source: req.body.source || 'web'
        });

        await newReport.save();

        await User.findByIdAndUpdate(userId, {
            $inc: { totalScans: 1 }
        });

        res.json({
            success: true,
            report: newReport
        });

    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({
            success: false,
            message: 'Error analyzing email'
        });
    }
};