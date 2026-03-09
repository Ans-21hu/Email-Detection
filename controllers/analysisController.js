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
        headerAnalysis: headers || {},
        recommendations: []
    };

    // Expanded list of suspicious phishing keywords
    const suspiciousKeywords = [
        'password', 'urgent', 'immediately', 'click here', 'verify', 'account',
        'suspended', 'locked', 'security', 'login', 'confirm', 'update',
        'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
        'blocked', 'deleted', 'unusual', 'detected', 'verification', 'renew',
        'expire', 'alert', 'notice', 'action required', 'billing', 'statement'
    ];

    const maliciousKeywords = [
        'wire transfer', 'bitcoin', 'crypto', 'phishing', 'virus', 'malware',
        'ransomware', 'trojan', 'exploit', 'hack', 'breach', 'compromised',
        'credentials', 'secret', 'hacked', 'stolen', 'unauthorized'
    ];

    let foundSuspicious = 0;
    let foundMalicious = 0;

    const contentLower = content.toLowerCase();
    const subjectLower = subject.toLowerCase();
    const senderLower = sender.toLowerCase();

    // Analyze sender — improved extraction and impersonation check
    let senderDomain = '';
    const domainMatch = senderLower.match(/@([^>\s]+)/);
    if (domainMatch) {
        senderDomain = domainMatch[1].replace('>', '').trim();
    } else {
        senderDomain = senderLower.split('@')[1] || '';
    }

    const suspiciousDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];
    const trustedDomains = ['company.com', 'organization.org', 'edu.in', 'mailxpose.tech'];

    details.senderAnalysis.domain = senderDomain;
    const isGenericDomain = suspiciousDomains.includes(senderDomain);
    details.senderAnalysis.isSuspiciousDomain = isGenericDomain;

    // Impersonation check: Generic domain + Official-sounding name
    const officialNames = ['support', 'admin', 'security', 'service', 'account', 'verify', 'billing', 'official'];
    const hasOfficialName = officialNames.some(name => senderLower.includes(name));

    if (isGenericDomain && hasOfficialName) {
        riskScore += 35;
        threats.push('sender_impersonation');
        details.indicators.push(`Sender Impersonation: "${sender}" is using a generic ${senderDomain} address for an official-sounding name.`);
    }

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

    // Check for links — improved regex catches more URL formats
    const linkRegex = /https?:\/\/[^\s"'<>)\]]+|www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s"'<>)\]]*/g;
    const rawLinks = (content.match(linkRegex) || []).map(l => l.replace(/[.,;:!?]+$/, ''));
    // Also count DOM-extracted links supplied by the extension (catches hidden href links)
    const extractedLinks = Array.isArray(headers.extractedLinks) ? headers.extractedLinks : [];
    const allLinks = [...new Set([...rawLinks, ...extractedLinks])];
    details.contentAnalysis.linkCount = allLinks.length;

    if (allLinks.length > 0) {
        riskScore += Math.min(allLinks.length * 5, 20);
        threats.push('contains_links');
        details.indicators.push(`Found ${allLinks.length} link(s) in email (including hidden href links)`);
    }

    // Check for suspicious links — expanded list
    const suspiciousLinkPatterns = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'is.gd',
        'buff.ly', 'goo.gl', 't.co', 'fb.me', 'shorte.st', 'rb.gy',
        'cutt.ly', 'short.io', 'tiny.cc', 'shortener',
        '.xyz', '.top', '.club', '.online', '.download', '.gq', '.ml', '.tk', '.cf', '.ga'
    ];
    const suspiciousLinks = allLinks.filter(link =>
        suspiciousLinkPatterns.some(p => link.toLowerCase().includes(p))
    );

    if (suspiciousLinks.length > 0) {
        riskScore += 25; // Increased from 15
        threats.push('suspicious_links_detected');
        details.indicators.push(`Found ${suspiciousLinks.length} suspicious/shortened links`);

        // Bonus for multiple suspicious links
        if (suspiciousLinks.length > 2) riskScore += 15;
    }

    // Heuristic link check (Per-link score)
    allLinks.forEach(link => {
        const lowerLink = link.toLowerCase();
        // Brand impersonation check
        const brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'netflix', 'bank'];
        if (brands.some(b => lowerLink.includes(b) && !lowerLink.includes(`${b}.com`) && !lowerLink.includes(`${b}.co`))) {
            riskScore += 20;
            details.indicators.push(`Possible brand impersonation in URL: ${link}`);
        }
        // Suspicious TLD check
        const riskyTlds = ['.xyz', '.top', '.club', '.online', '.gq', '.ml', '.tk', '.ga', '.icu'];
        if (riskyTlds.some(t => lowerLink.endsWith(t) || lowerLink.includes(t + '/'))) {
            riskScore += 15;
            details.indicators.push(`Suspicious TLD in URL: ${link}`);
        }
    });

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

    // Add scores from keywords — increased weights
    riskScore += foundSuspicious * 8; // Increased from 5
    riskScore += foundMalicious * 20; // Increased from 15

    // Urgency bonus if many suspicious factors combined
    if (foundSuspicious > 2 && allLinks.length > 0) {
        riskScore += 15;
        details.indicators.push('Combined threat signals: Urgency + Links');
    }

    // Cap risk score at 100
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    // Determine risk level and status
    let riskLevel = 'low';
    let status = 'safe';

    if (riskScore >= 70) {
        riskLevel = 'high';
        status = 'malicious';
        details.recommendations.push('🚨 **CRITICAL RISK**: This email shows multiple phishing indicators. DO NOT INTERACT!');
        details.recommendations.push('📞 **Report immediately** to your IT security team.');
        details.recommendations.push('🗑️ **Delete permanently** after reporting.');
        details.recommendations.push('🔒 **Change passwords** if you clicked any links.');
    } else if (riskScore >= 40) {
        riskLevel = 'medium';
        status = 'suspicious';
        details.recommendations.push('⚠️ **HIGH RISK**: Exercise extreme caution with this email.');
        details.recommendations.push('🔍 **Verify sender** through official channels (website, phone call).');
        details.recommendations.push('🔗 **DO NOT click links** - manually type website addresses if needed.');
        details.recommendations.push('📧 **Check email headers** for SPF/DKIM authentication.');
    } else if (riskScore >= 20) {
        riskLevel = 'medium'; // Treating > 20 as medium for better warning
        status = 'suspicious';
        details.recommendations.push('👀 **MODERATE RISK**: Be vigilant with this email.');
        details.recommendations.push('🏢 **Verify company** through their official website.');
        details.recommendations.push('🔐 **Watch for requests** for personal or financial information.');
    } else {
        riskLevel = 'low';
        status = 'safe';
        details.recommendations.push('✅ **LOW RISK**: Email appears legitimate.');
        details.recommendations.push('👍 **No immediate action** required.');
        details.recommendations.push('🔒 **Maintain good practices** - always verify unusual requests.');
    }

    if (allLinks.length > 0) {
        details.recommendations.push(`🔗 **Links Detected**: ${allLinks.length} links found - always hover before clicking.`);
    }

    if (hasSuspiciousAttachment) {
        details.recommendations.push('🎯 **Malicious Attachment**: DO NOT open the attachment. It contains executable or risky code.');
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
        // Pass extractedLinks (DOM-harvested hidden links) into headers so analyzeEmail can use them
        const enrichedHeaders = { ...(headers || {}), extractedLinks: req.body.extractedLinks || [] };
        const analysisResult = analyzeEmail(content || '', sender, subject, enrichedHeaders);
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

// Get all reports for the current user
exports.getAllReports = async (req, res) => {
    try {
        const userId = req.user.id;
        const reports = await Report.find({ userId }).sort({ createdAt: -1 });
        res.json({ success: true, reports });
    } catch (error) {
        console.error('Get all reports error:', error);
        res.status(500).json({ success: false, message: 'Error fetching reports' });
    }
};

// Get a single report by ID
exports.getReportById = async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user.id });
        if (!report) {
            return res.status(404).json({ success: false, message: 'Report not found' });
        }
        res.json({ success: true, report });
    } catch (error) {
        console.error('Get report error:', error);
        res.status(500).json({ success: false, message: 'Error fetching report' });
    }
};

// Delete a report
exports.deleteReport = async (req, res) => {
    try {
        const result = await Report.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!result) {
            return res.status(404).json({ success: false, message: 'Report not found' });
        }
        res.json({ success: true, message: 'Report deleted successfully' });
    } catch (error) {
        console.error('Delete report error:', error);
        res.status(500).json({ success: false, message: 'Error deleting report' });
    }
};

// Get dashboard stats for the user
exports.getDashboardStats = async (req, res) => {
    try {
        const userId = req.user.id;
        const reports = await Report.find({ userId });

        const totalScans = reports.length;
        const threatsFound = reports.filter(r => r.status !== 'safe').length;
        const successRate = totalScans > 0 ? Math.round(((totalScans - threatsFound) / totalScans) * 100) : 100;

        const totalResponseTime = reports.reduce((acc, r) => acc + (r.analysisTime || 0), 0);
        const avgResponseTime = totalScans > 0 ? (totalResponseTime / (totalScans * 1000)).toFixed(2) : "0.00";

        const stats = {
            totalScans,
            threatsFound,
            successRate: `${successRate}%`,
            avgResponseTime: `${avgResponseTime}s`,
            totalScansChange: totalScans > 0 ? '+100%' : 'No data yet', // Mocking change for now
            threatsFoundChange: threatsFound > 0 ? '+100%' : 'No data yet',
            successRateChange: 'Stable',
            avgResponseTimeChange: '-0.2s',
            recentActivity: reports.slice(0, 5)
        };

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ success: false, message: 'Error fetching dashboard stats' });
    }
};

// Get global stats (total scans across system)
exports.getGlobalStats = async (req, res) => {
    try {
        const totalReports = await Report.countDocuments();
        const totalUsers = await User.countDocuments();

        res.json({
            success: true,
            stats: {
                totalAnalyses: totalReports,
                totalUsers: totalUsers,
                protectedAccounts: totalUsers * 5 // Mocking some value
            }
        });
    } catch (error) {
        console.error('Global stats error:', error);
        res.status(500).json({ success: false, message: 'Error fetching global stats' });
    }
};