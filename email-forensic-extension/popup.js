const API_BASE_URL = 'https://mailxpose.tech/api';

// DOM Elements
const setupSection = document.getElementById('setupSection');
const inputSection = document.getElementById('inputSection');
const analysisSection = document.getElementById('analysisSection');
const analysisResults = document.getElementById('analysisResults');
const emailInput = document.getElementById('emailInput');
const loadingOverlay = document.getElementById('loadingOverlay');
const loadingText = document.getElementById('loadingText');
const loadingSubtext = document.getElementById('loadingSubtext');
const progressFill = document.getElementById('progressFill');
const statusText = document.getElementById('statusText');
const emailCount = document.getElementById('emailCount');
const scanCount = document.getElementById('scanCount');
const threatCount = document.getElementById('threatCount');
const successRate = document.getElementById('successRate');

// Dashboard linking elements
const dashboardEmail = document.getElementById('dashboardEmail');
const dashboardPassword = document.getElementById('dashboardPassword');
const linkDashboardBtn = document.getElementById('linkDashboardBtn');


// State
let currentAnalysis = null;
let analysisHistory = [];
let extensionToken = null;
let userInfo = null;
let isLinked = false;
let currentVisibleView = null;

// Initialize
function init() {
    console.log('🔧 Email Forensic Analyzer Popup Initialized');

    // Add animation styles
    addAnimationStyles();

    // Load saved email and stats
    loadSavedData();

    // Set up event listeners
    setupEventListeners();

    // Update status
    updateStatus('Ready to analyze emails');

    // Check for new email automatically
    setTimeout(() => {
        checkForRecentEmail();
    }, 500);

    // Check dashboard connection periodically
    setInterval(checkDashboardConnection, 1000);

    // Listen for messages from background
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'popupOpened') {
            console.log('Popup opened message:', request.message);
        }
        // Force check when message received
        checkDashboardConnection();
    });

    // Initial check
    checkDashboardConnection();

    // React to logout in other contexts (e.g. background script)
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && (changes.isLinked || changes.apiKey)) {
            console.log('Auth state change detected, updating UI...');
            checkDashboardConnection();
        }
    });
}

// Centralized View Management
function showView(viewId) {
    if (currentVisibleView === viewId) return;

    const views = ['setupSection', 'inputSection', 'analysisSection'];
    views.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.style.display = (id === viewId) ? 'block' : 'none';
        }
    });

    currentVisibleView = viewId;

    // Reset scroll positions when switching views
    const activeView = document.getElementById(viewId);
    if (activeView) activeView.scrollTop = 0;
}

// Add animation styles to document
function addAnimationStyles() {
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .risk-score-animation {
            animation: pulse 2s infinite;
        }
    `;
    document.head.appendChild(style);
}

// Load saved data
function loadSavedData() {
    chrome.storage.local.get([
        'currentEmail',
        'scanCount',
        'threatCount',
        'recentScans',
        'savedReports',
        'lastAnalysis'
    ], (result) => {
        console.log('Loaded saved data:', result);

        if (result.currentEmail) {
            try {
                const email = JSON.parse(result.currentEmail);
                emailInput.value = formatEmailPreview(email);
                console.log('Loaded email:', email.subject);
            } catch (e) {
                console.log('Email parsing error:', e);
                emailInput.value = result.currentEmail.substring(0, 1000);
            }
        }

        // Update stats
        updateStats(result);

        // Load analysis history
        if (result.savedReports) {
            analysisHistory = result.savedReports;
        }

        // Load last analysis if exists
        if (result.lastAnalysis) {
            try {
                currentAnalysis = JSON.parse(result.lastAnalysis);
                console.log('Loaded last analysis');
            } catch (e) {
                console.log('Last analysis parsing error:', e);
            }
        }
    });
}

// Format email preview
function formatEmailPreview(email) {
    if (!email) return '';

    const maxLength = 1500;
    let preview = `📧 Subject: ${email.subject || 'No Subject'}\n`;
    preview += `👤 From: ${email.from || 'Unknown Sender'}\n`;
    preview += `📅 Date: ${email.date || 'Unknown Date'}\n`;
    preview += `🔗 URL: ${email.url || 'N/A'}\n`;
    preview += `─`.repeat(50) + `\n\n`;

    // Trim body if too long
    let body = email.body || '';
    if (body.length > maxLength) {
        body = body.substring(0, maxLength) + '... [truncated]';
    }

    preview += body;
    return preview;
}

// Update statistics
function updateStats(data) {
    const scans = data.scanCount || 0;
    const threats = data.threatCount || 0;
    const successPercentage = scans > 0 ? Math.round(((scans - threats) / scans) * 100) : 100;

    // Animate count
    animateCount('scanCount', scans);
    animateCount('threatCount', threats);
    successRate.textContent = `${successPercentage}%`;
    emailCount.textContent = `${scans} emails analyzed`;

    // Update threat count color
    if (threats > 0) {
        threatCount.style.color = '#ef476f';
        threatCount.style.fontWeight = 'bold';
    }
}

// Animate number counting
function animateCount(elementId, target) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const current = parseInt(element.textContent) || 0;
    if (current === target) return;

    const duration = 800; // ms
    const steps = 40;
    const increment = (target - current) / steps;
    let currentStep = 0;

    const timer = setInterval(() => {
        currentStep++;
        const newValue = Math.round(current + (increment * currentStep));
        element.textContent = newValue;

        if (currentStep >= steps) {
            element.textContent = target;
            clearInterval(timer);
        }
    }, duration / steps);
}

// Set up event listeners
function setupEventListeners() {
    // Dashboard Linking
    if (linkDashboardBtn) {
        linkDashboardBtn.addEventListener('click', handleLinkDashboard);
    }

    // Create Account Button
    const createAccountBtn = document.getElementById('createAccountBtn');
    if (createAccountBtn) {
        createAccountBtn.addEventListener('click', () => {
            // Open registration page in a new tab
            chrome.tabs.create({ url: 'https://mailxpose.tech/registration.html' });
        });
    }

    // Main buttons
    document.getElementById('clearBtn').addEventListener('click', clearInput);
    document.getElementById('getCurrentEmailBtn').addEventListener('click', getCurrentGmail);
    document.getElementById('analyzeBtn').addEventListener('click', startAnalysis);

    // Quick action buttons
    document.getElementById('scanAllBtn').addEventListener('click', () =>
        showFeaturePopup('Complete inbox scanning will be available soon!', '🔍'));
    document.getElementById('settingsBtn').addEventListener('click', () =>
        showFeaturePopup('Settings panel will be available in next update!', '⚙️'));
    document.getElementById('reportsBtn').addEventListener('click', showReports);

    // Back button
    document.getElementById('backBtn').addEventListener('click', goBack);

    // Auto-focus textarea
    if (emailInput) {
        emailInput.addEventListener('focus', () => {
            emailInput.style.borderColor = '#4361ee';
            emailInput.style.boxShadow = '0 0 0 3px rgba(67, 97, 238, 0.1)';
        });

        emailInput.addEventListener('blur', () => {
            emailInput.style.borderColor = '#e9ecef';
            emailInput.style.boxShadow = 'none';
        });

        // Enter key to analyze
        emailInput.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                startAnalysis();
            }
        });
    }

    console.log('✅ All event listeners set up');
}

// Get current Gmail
function getCurrentGmail() {
    updateStatus('Fetching current email...');
    showLoading(true, 'Fetching Current Email', 'Reading from Gmail...');

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0] || !tabs[0].url.includes('mail.google.com')) {
            showLoading(false);
            showNotification('Please open Gmail first', 'error');
            emailInput.value = 'Error: Please navigate to Gmail and open an email to analyze.';
            updateStatus('Error: Not on Gmail');
            return;
        }

        chrome.tabs.sendMessage(tabs[0].id, { action: 'getCurrentEmail' }, (response) => {
            showLoading(false);

            if (chrome.runtime.lastError) {
                console.error('Error:', chrome.runtime.lastError);
                showNotification('Please refresh Gmail page and try again', 'error');
                emailInput.value = 'Error: Could not fetch email. Please make sure you are on Gmail page and refresh it.';
                updateStatus('Error: Gmail not ready');
                return;
            }

            if (response && response.emailContent) {
                try {
                    const emailData = JSON.parse(response.emailContent);
                    emailInput.value = formatEmailPreview(emailData);

                    // Save to storage
                    chrome.storage.local.set({
                        currentEmail: response.emailContent,
                        lastFetched: new Date().toISOString(),
                        lastEmailSubject: emailData.subject
                    });

                    showNotification('✅ Email fetched successfully!', 'success');
                    updateStatus('Email loaded - Ready to analyze');

                    // Auto-scroll to top
                    emailInput.scrollTop = 0;

                } catch (e) {
                    console.error('Parsing error:', e);
                    emailInput.value = response.emailContent.substring(0, 2000);
                    showNotification('Email fetched successfully!', 'success');
                    updateStatus('Email loaded');
                }
            } else {
                showNotification('No email found. Please open an email first.', 'warning');
                emailInput.value = 'Please open an email in Gmail and try again. The button should appear when you open an email.';
                updateStatus('No email detected');
            }
        });
    });
}

// Start analysis
async function startAnalysis() {
    const emailContent = emailInput.value.trim();

    if (!emailContent) {
        showNotification('Please enter email content first', 'error');
        emailInput.focus();
        return;
    }

    if (emailContent.length < 20) {
        showNotification('Email content seems too short', 'warning');
    }

    showLoading(true, 'Analyzing Email', 'Running advanced security scan...');
    updateStatus('Analysis in progress...');

    // Progress animation
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 8;
        if (progress <= 100) {
            progressFill.style.width = `${progress}%`;
        }
        if (progress >= 100) {
            clearInterval(progressInterval);
        }
    }, 150);

    try {
        // First try backend API
        const apiResult = await tryBackendAnalysis(emailContent);

        if (apiResult.success) {
            // Backend analysis successful
            currentAnalysis = apiResult;
            showLoading(false);
            displayAnalysisResults(apiResult);
            updateStatus('Analysis complete (AI Engine)');
            showNotification('✅ Analysis complete using AI Engine!', 'success');

            // Update scan count
            updateScanCount(true, apiResult.is_suspicious || apiResult.is_phishing);

        } else {
            // Fallback to local analysis
            console.log('Using local analysis fallback');
            const localResult = analyzeLocally(emailContent);
            currentAnalysis = localResult;

            setTimeout(() => {
                showLoading(false);
                displayAnalysisResults(localResult);
                updateStatus('Analysis complete (Local Engine)');
                showNotification('✅ Analysis complete using local engine!', 'success');

                // Update scan count
                updateScanCount(true, localResult.is_suspicious || localResult.is_phishing);
            }, 500);
        }

    } catch (error) {
        console.error('Analysis error:', error);

        // Check if usage limit exceeded
        if (error.isLimitExceeded || error.message.includes('Usage limit exceeded')) {
            showLoading(false);
            showNotification('❌ Daily limit exceeded! Please upgrade.', 'error');
            updateStatus('Daily limit reached');

            // Show upgrade modal or message
            showFeaturePopup(`
                <h3 style="margin-bottom: 10px; color: #ef4444;">Daily Limit Reached</h3>
                <p>You have reached your daily scan limit.</p>
                <p>Upgrade to Pro for 100 scans/day!</p>
                <button onclick="window.open('https://mailxpose.tech/profile.html', '_blank')" 
                    style="background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; margin-top: 15px; cursor: pointer;">
                    Upgrade Plan
                </button>
            `, '🛑');
            return;
        }

        // Final fallback for other errors
        const localResult = analyzeLocally(emailContent);
        currentAnalysis = localResult;

        setTimeout(() => {
            showLoading(false);
            displayAnalysisResults(localResult);
            updateStatus('Analysis complete');
            showNotification('✅ Analysis completed (Offline Mode)', 'success');

            // Update scan count
            updateScanCount(true, localResult.is_suspicious || localResult.is_phishing);
        }, 500);
    }
}

// Try backend API analysis
async function tryBackendAnalysis(emailContent) {
    try {
        // Ensure we are authenticated
        if (!extensionToken) {
            const hasAuth = await reauthenticate();
            if (!hasAuth) {
                throw new Error('Not connected to dashboard');
            }
        }

        // Extract basic info for report
        const subject = extractSubject(emailContent) || 'Quick Scan';
        const sender = extractSender(emailContent) || 'Unknown Sender';

        const response = await fetch(`${API_BASE_URL}/analysis/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${extensionToken}`,
                'x-extension-key': (userInfo || {}).apiKey
            },
            body: JSON.stringify({
                content: emailContent,
                subject: subject,
                sender: sender,
                source: 'extension'
            }),
            signal: AbortSignal.timeout(10000)
        });

        if (response.status === 401 || response.status === 403) {
            // Token expired, try one more time
            const reauthSuccess = await reauthenticate();
            if (!reauthSuccess) throw new Error('Authentication failed');

            const retryResponse = await fetch(`${API_BASE_URL}/analysis/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${extensionToken}`,
                    'x-extension-key': (userInfo || {}).apiKey
                },
                body: JSON.stringify({
                    content: emailContent,
                    subject: subject,
                    sender: sender,
                    source: 'extension'
                })
            });

            if (!retryResponse.ok) throw new Error('Analysis failed after retry');
            return transformBackendResult(await retryResponse.json());
        }

        if (response.status === 429) {
            const data = await response.json();
            const error = new Error(data.message || 'Usage limit exceeded');
            error.isLimitExceeded = true;
            error.limits = data.limits;
            error.resetTime = data.resetTime;
            throw error;
        }

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        return transformBackendResult(await response.json());

    } catch (error) {
        console.log('Backend API failed, using local analysis:', error.message);
        throw error;
    }
}

// Transform backend result to frontend format
function transformBackendResult(result) {
    if (!result.success) return result;

    console.log('Transforming backend result:', result);

    // Handle cases where data might be in 'report' or at top level
    const data = result.report || result;
    const detailsObj = data.details || {};

    // Merge indicators and warnings from multiple possible locations
    const indicatorsArr = [
        ...(Array.isArray(data.indicators) ? data.indicators : []),
        ...(Array.isArray(detailsObj.indicators) ? detailsObj.indicators : [])
    ];

    const warningsArr = [
        ...(Array.isArray(data.warnings) ? data.warnings : []),
        ...(Array.isArray(detailsObj.warnings) ? detailsObj.warnings : []),
        ...(Array.isArray(data.threats) ? data.threats.filter(t => typeof t === 'string' && !['Phishing', 'Spoofing'].includes(t)) : [])
    ];

    const detailedFindings = [
        ...(Array.isArray(data.details) ? data.details : []),
        ...(Array.isArray(detailsObj.details) ? detailsObj.details : []),
        ...(Array.isArray(data.findings) ? data.findings : [])
    ];

    const technicalArr = [
        ...(Array.isArray(data.technical) ? data.technical : []),
        ...(Array.isArray(detailsObj.technical) ? detailsObj.technical : []),
        ...(Array.isArray(data.metadata) ? data.metadata : []),
        ...(data.senderDomain ? [`Sender Domain: ${data.senderDomain}`] : [])
    ];

    // If details are empty but we have indicators/warnings, populate them for the UI
    if (detailedFindings.length === 0) {
        indicatorsArr.forEach(ind => {
            if (typeof ind === 'string') {
                detailedFindings.push({
                    type: 'indicator',
                    title: 'Security Indicator',
                    description: ind,
                    severity: 'medium'
                });
            } else if (typeof ind === 'object') {
                detailedFindings.push(ind);
            }
        });

        warningsArr.forEach(warn => {
            if (typeof warn === 'string') {
                detailedFindings.push({
                    type: 'warning',
                    title: 'Security Warning',
                    description: warn,
                    severity: 'high'
                });
            } else if (typeof warn === 'object') {
                detailedFindings.push(warn);
            }
        });
    }

    return {
        success: true,
        report_id: data._id || data.id || 'REPORT-' + Date.now().toString().slice(-8),
        risk_score: data.riskScore || data.risk_score || 0,
        risk_level: (data.riskLevel || data.risk_level || 'medium').toUpperCase(),
        is_suspicious: data.status === 'suspicious' || data.status === 'malicious' || data.is_suspicious || (data.riskScore > 40),
        is_phishing: (data.threats || []).includes('Phishing') || data.is_phishing || (data.riskScore > 60),
        is_spoofed: (data.threats || []).includes('Spoofing') || data.is_spoofed,
        warnings: [...new Set(warningsArr.filter(w => typeof w === 'string'))],
        indicators: [...new Set(indicatorsArr.filter(i => typeof i === 'string'))],
        details: detailedFindings,
        technical: [...new Set(technicalArr.filter(t => typeof t === 'string'))],
        recommendations: data.recommendations || detailsObj.recommendations || [],
        analysis_date: data.analysisDate || data.analysis_date || new Date().toISOString(),
        analyzed_by: 'AI Cloud Engine',
        confidence: data.confidence || '98%',
        subject: data.subject,
        from: data.sender || data.from
    };
}

// Helper for promisified storage
const storage = {
    get: (keys) => new Promise((resolve) => chrome.storage.local.get(keys, resolve)),
    set: (items) => new Promise((resolve) => chrome.storage.local.set(items, resolve))
};

// Handle dashboard linking
async function handleLinkDashboard() {
    const email = dashboardEmail.value.trim();
    const password = dashboardPassword.value.trim();

    if (!email || !password) {
        showNotification('Please enter email and password', 'error');
        return;
    }

    updateStatus('Connecting to dashboard...');
    linkDashboardBtn.textContent = 'Connecting...';
    linkDashboardBtn.disabled = true;

    try {
        // 1. Login to get user ID
        console.log('🔐 Attempting login to:', `${API_BASE_URL}/auth/login`);
        const loginResponse = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        console.log('📥 Login response status:', loginResponse.status);
        const loginData = await loginResponse.json();
        console.log('📦 Login data:', loginData);

        if (!loginData.success) throw new Error(loginData.message || 'Login failed');

        const userId = loginData.user.id;
        const subPlan = loginData.user.subscriptionPlan;

        // 2. Generate or get Extension ID
        let startData = await storage.get('extensionId');
        let extensionId = startData.extensionId;

        if (!extensionId) {
            extensionId = 'ext_' + Math.random().toString(36).substr(2, 9);
            await storage.set({ extensionId });
        }

        // 3. Register Extension
        console.log('📝 Attempting extension registration to:', `${API_BASE_URL}/extension/register`);
        console.log('📤 Registration payload:', { userId, extensionId, subscriptionPlan: subPlan });

        const registerResponse = await fetch(`${API_BASE_URL}/extension/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userId,
                extensionId,
                deviceInfo: { userAgent: navigator.userAgent },
                subscriptionPlan: subPlan
            })
        });

        console.log('📥 Registration response status:', registerResponse.status);
        const registerData = await registerResponse.json();
        console.log('📦 Registration data:', registerData);
        let extensionData = null;

        if (registerData.success) {
            extensionData = registerData.extension;
        } else if (registerData.message === 'Extension already registered') {
            // Collision handling
            console.log('Extension collision, generating new ID...');
            extensionId = 'ext_' + Math.random().toString(36).substr(2, 9);
            await storage.set({ extensionId });

            // Retry register
            const retryResponse = await fetch(`${API_BASE_URL}/extension/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userId,
                    extensionId,
                    deviceInfo: { userAgent: navigator.userAgent },
                    subscriptionPlan: subPlan
                })
            });
            const retryData = await retryResponse.json();
            if (retryData.success) {
                extensionData = retryData.extension;
            } else {
                throw new Error(retryData.message || 'Registration retry failed');
            }
        } else {
            throw new Error(registerData.message || 'Registration failed');
        }

        // Save Credentials
        await storage.set({
            apiKey: extensionData.apiKey,
            extensionId: extensionData.extensionId,
            userId: userId,
            linkedEmail: email,
            isLinked: true
        });

        userInfo = { apiKey: extensionData.apiKey, ...extensionData };
        isLinked = true;

        // Initial re-auth to get tokens
        await reauthenticate();

        showNotification('✅ Dashboard linked successfully!', 'success');

        // Update UI
        showView('inputSection');
        checkDashboardConnection();

    } catch (error) {
        console.error('❌ Dashboard linking error:', error);
        console.error('Error details:', {
            message: error.message,
            stack: error.stack,
            name: error.name
        });
        showNotification('Connection failed: ' + error.message, 'error');
        linkDashboardBtn.textContent = 'Link Dashboard';
        linkDashboardBtn.disabled = false;
        updateStatus('Connection failed');
    }
}

// Re-authenticate
async function reauthenticate() {
    try {
        const data = await storage.get(['extensionId', 'apiKey']);
        if (data.extensionId && data.apiKey) {
            const response = await fetch(`${API_BASE_URL}/extension/auth`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    extensionId: data.extensionId,
                    apiKey: data.apiKey
                })
            });
            const result = await response.json();
            if (result.success) {
                extensionToken = result.token;
                userInfo = { apiKey: data.apiKey, ...result.extension };
                isLinked = true;
                return true;
            }
        }
        return false;
    } catch (e) {
        console.error('Re-auth failed', e);
        return false;
    }
}

// Check connection status
// Check connection status
async function checkDashboardConnection() {
    const data = await storage.get(['isLinked', 'linkedEmail']);

    const previousLinkedState = isLinked;
    isLinked = !!data.isLinked;

    if (isLinked) {
        // Only switch to input view if we just linked or if we were on the setup page
        if (!previousLinkedState || currentVisibleView === 'setupSection' || !currentVisibleView) {
            showView('inputSection');
        }

        // Show linked status indicator if not already present
        if (!document.getElementById('linkedStatusIndicator')) {
            const statusEl = document.createElement('div');
            statusEl.id = 'linkedStatusIndicator';
            statusEl.innerHTML = `<small style="color: #4361ee; font-weight: 500;">Linked: ${data.linkedEmail}</small>`;
            statusEl.style.position = 'absolute';
            statusEl.style.top = '10px';
            statusEl.style.left = '10px';
            document.body.appendChild(statusEl);
        }

    } else {
        // Handle unlinked state
        isLinked = false;

        showView('setupSection');
    }
}

// Local analysis
function analyzeLocally(emailContent) {
    console.log('Running local analysis...');

    let riskScore = 0;
    const warnings = [];
    const indicators = [];
    const details = [];
    const technical = [];

    const lowerContent = emailContent.toLowerCase();

    // Extract basic info
    const subject = extractSubject(emailContent);
    const sender = extractSender(emailContent);
    const senderDomain = extractDomain(sender);
    const urls = extractUrls(emailContent);

    // 1. Check for phishing keywords
    const phishingKeywords = [
        'urgent', 'immediately', 'verify', 'confirm', 'password',
        'login', 'account', 'suspended', 'limited', 'security',
        'click here', 'update now', 'action required', 'new device',
        'login detected', 'secure your account', 'unusual activity',
        'payment', 'invoice', 'overdue', 'bank', 'wire transfer'
    ];

    const foundKeywords = phishingKeywords.filter(keyword => lowerContent.includes(keyword));

    if (foundKeywords.length > 0) {
        riskScore += foundKeywords.length * 8;
        indicators.push(`Found ${foundKeywords.length} suspicious keywords`);

        foundKeywords.forEach(keyword => {
            details.push({
                type: 'keyword',
                title: 'Suspicious Keyword',
                description: `"${keyword}" detected - commonly used in phishing emails`,
                severity: 'medium'
            });
        });
    }

    // 2. Check for urgency indicators
    const exclamationCount = (emailContent.match(/!/g) || []).length;
    if (exclamationCount > 3) {
        riskScore += 15;
        indicators.push('Multiple exclamation marks detected');
        details.push({
            type: 'urgency',
            title: 'Urgency Tactics',
            description: `${exclamationCount} exclamation marks - common phishing tactic to create urgency`,
            severity: 'medium'
        });
    }

    // 3. URL Analysis
    if (urls.length > 0) {
        riskScore += urls.length * 10;
        warnings.push(`Found ${urls.length} links - verify before clicking`);

        const suspiciousUrls = urls.filter(isSuspiciousUrl);
        if (suspiciousUrls.length > 0) {
            riskScore += suspiciousUrls.length * 20;
            warnings.push(`Found ${suspiciousUrls.length} suspicious URLs`);

            suspiciousUrls.forEach((url, index) => {
                details.push({
                    type: 'url',
                    title: `Suspicious Link ${index + 1}`,
                    description: `${url.substring(0, 60)}... - Shortened or suspicious domain`,
                    severity: 'high'
                });
            });
        }

        // Technical details about URLs
        technical.push(`Total URLs: ${urls.length}`);
        technical.push(`Suspicious URLs: ${suspiciousUrls.length}`);
        technical.push(`HTTPS URLs: ${urls.filter(url => url.startsWith('https://')).length}`);
    }

    // 4. Check for generic greetings
    const genericGreetings = ['dear user', 'dear customer', 'valued member', 'account holder', 'valued customer'];
    if (genericGreetings.some(greeting => lowerContent.includes(greeting))) {
        riskScore += 10;
        indicators.push('Generic greeting detected');
        details.push({
            type: 'greeting',
            title: 'Generic Greeting',
            description: 'Impersonal greeting - common in mass phishing campaigns',
            severity: 'low'
        });
    }

    // 5. Check for grammatical errors
    const grammarIssues = checkGrammarIssues(emailContent);
    if (grammarIssues.length > 0) {
        riskScore += grammarIssues.length * 5;
        indicators.push('Grammar/spelling issues detected');
        grammarIssues.forEach(issue => {
            details.push({
                type: 'grammar',
                title: 'Grammar Issue',
                description: issue,
                severity: 'low'
            });
        });
    }

    // 6. Check email structure
    if (!emailContent.includes('@') || !emailContent.includes('.')) {
        riskScore += 10;
        warnings.push('Email structure appears incomplete');
        details.push({
            type: 'structure',
            title: 'Structure Issue',
            description: 'Email appears to have incomplete or malformed structure',
            severity: 'medium'
        });
    }

    // 7. Check for personal information requests
    const piiKeywords = ['ssn', 'social security', 'credit card', 'bank account', 'password', 'pin', 'otp', 'cvv'];
    const foundPII = piiKeywords.filter(k => lowerContent.includes(k));
    if (foundPII.length > 0) {
        riskScore += 30;
        warnings.push(`Email requests sensitive information (${foundPII.length} indicators)`);
        foundPII.forEach(pii => {
            details.push({
                type: 'pii',
                title: 'Sensitive Info Request',
                description: `Request for "${pii}" detected - never share sensitive information via email`,
                severity: 'high'
            });
        });
    }

    // 8. Check sender information
    if (senderDomain && senderDomain !== 'unknown') {
        technical.push(`Sender Domain: ${senderDomain}`);

        // Check for domain mismatches
        if (urls.length > 0) {
            const externalDomains = urls.filter(url => {
                const urlDomain = extractUrlDomain(url);
                return urlDomain && urlDomain !== senderDomain;
            });

            if (externalDomains.length > 0) {
                riskScore += 15;
                indicators.push('Links point to different domains than sender');
                technical.push(`External domains in links: ${externalDomains.length}`);
            }
        }
    }

    // Calculate final risk score (cap at 100)
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    // Determine risk level
    let riskLevel = 'LOW';
    if (riskScore >= 70) riskLevel = 'HIGH';
    else if (riskScore >= 40) riskLevel = 'MEDIUM';

    // Determine overall status
    const isSuspicious = riskScore > 40;
    const isPhishing = riskScore > 60;
    const isSpoofed = riskScore > 50 && (grammarIssues.length > 2 || foundKeywords.length > 3);

    // Generate detailed report
    return {
        success: true,
        report_id: 'LOCAL-' + Date.now().toString().slice(-8),
        risk_score: riskScore,
        risk_level: riskLevel,
        warnings: warnings,
        indicators: indicators,
        details: details,
        technical: technical,
        is_suspicious: isSuspicious,
        is_phishing: isPhishing,
        is_spoofed: isSpoofed,
        recommendations: generateLocalRecommendations(riskScore, foundKeywords.length, urls.length, isPhishing),
        analysis_date: new Date().toISOString(),
        analyzed_by: 'Local AI Engine v2.0',
        confidence: Math.max(75, 100 - riskScore) + '%',
        senderDomain: senderDomain,
        subject: subject,
        from: sender,
        totalUrls: urls.length,
        suspiciousUrls: urls.filter(isSuspiciousUrl).length,
        features_checked: foundKeywords.length + urls.length + grammarIssues.length
    };
}

// Helper functions for local analysis
function extractSubject(emailContent) {
    const subjectMatch = emailContent.match(/Subject:\s*(.*)/i) ||
        emailContent.match(/📧 Subject:\s*(.*)/) ||
        emailContent.split('\n')[0].match(/^(.*)/);
    return subjectMatch ? subjectMatch[1].trim() : 'No Subject';
}

function extractSender(emailContent) {
    const senderMatch = emailContent.match(/From:\s*(.*)/i) ||
        emailContent.match(/👤 From:\s*(.*)/) ||
        emailContent.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return senderMatch ? senderMatch[1].trim() : 'Unknown Sender';
}

function extractDomain(email) {
    const match = email.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1] : 'unknown';
}

function extractUrls(text) {
    const urlRegex = /https?:\/\/[^\s"'<>]+/g;
    return text.match(urlRegex) || [];
}

function extractUrlDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace('www.', '');
    } catch {
        return null;
    }
}

function isSuspiciousUrl(url) {
    const suspiciousPatterns = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'is.gd',
        'buff.ly', 'goo.gl', 't.co', 'fb.me', 'shorte.st',
        '.xyz', '.top', '.club', '.online', '.download', '.gq', '.ml', '.tk'
    ];

    const lowerUrl = url.toLowerCase();
    return suspiciousPatterns.some(pattern => lowerUrl.includes(pattern));
}

function checkGrammarIssues(text) {
    const issues = [];

    // Excessive capitalization
    const excessiveCaps = (text.match(/[A-Z]{4,}/g) || []).length;
    if (excessiveCaps > 2) {
        issues.push('Excessive capitalization detected');
    }

    // Spacing issues
    const spacingIssues = (text.match(/  | \.| ,|,,|\.\./g) || []).length;
    if (spacingIssues > 3) {
        issues.push('Spacing/punctuation issues');
    }

    // Common misspellings
    const commonMisspellings = [
        { wrong: 'recieve', correct: 'receive' },
        { wrong: 'seperate', correct: 'separate' },
        { wrong: 'definately', correct: 'definitely' },
        { wrong: 'occured', correct: 'occurred' },
        { wrong: 'tommorow', correct: 'tomorrow' },
        { wrong: 'wierd', correct: 'weird' },
        { wrong: 'aquire', correct: 'acquire' }
    ];

    const lowerText = text.toLowerCase();
    const foundMisspellings = commonMisspellings.filter(item => lowerText.includes(item.wrong));
    if (foundMisspellings.length > 0) {
        issues.push(`Common misspellings: ${foundMisspellings.map(m => m.wrong).join(', ')}`);
    }

    return issues;
}

function generateLocalRecommendations(riskScore, keywordCount, urlCount, isPhishing) {
    const recommendations = [];

    if (riskScore > 60) {
        recommendations.push('🚨 **CRITICAL RISK**: This email shows multiple phishing indicators. DO NOT INTERACT!');
        recommendations.push('📞 **Report immediately** to your organization\'s IT security team or abuse@domain.com');
        recommendations.push('🗑️ **Delete permanently** after reporting - do not keep in any folder');
        recommendations.push('🔒 **Change passwords** if you clicked any links or entered information');
        recommendations.push('📋 **Monitor accounts** for suspicious activity in next 48 hours');
    } else if (riskScore > 40) {
        recommendations.push('⚠️ **HIGH RISK**: Exercise extreme caution with this email');
        recommendations.push('🔍 **Verify sender** through official channels (website, phone call)');
        recommendations.push('🔗 **DO NOT click links** - manually type website addresses if needed');
        recommendations.push('📧 **Check email headers** for SPF/DKIM authentication');
        recommendations.push('🏢 **Contact company directly** using contact info from official website');
    } else if (riskScore > 20) {
        recommendations.push('👀 **MODERATE RISK**: Be vigilant with this email');
        recommendations.push('🏢 **Verify company** through their official website (not via email links)');
        recommendations.push('🔐 **Watch for requests** for personal or financial information');
        recommendations.push('📱 **Use official apps** instead of clicking email links');
        recommendations.push('🔍 **Check sender email** for slight variations (e.g., gmail.com vs gma1l.com)');
    } else {
        recommendations.push('✅ **LOW RISK**: Email appears legitimate');
        recommendations.push('👍 **No immediate action** required');
        recommendations.push('🔒 **Maintain good practices** - always verify unusual requests');
        recommendations.push('📚 **Stay educated** about current phishing techniques');
    }

    if (keywordCount > 0) {
        recommendations.push(`🎣 **Phishing Keywords**: Found ${keywordCount} suspicious terms - common in scams`);
    }

    if (urlCount > 0) {
        recommendations.push(`🔗 **Links Detected**: ${urlCount} links found - always hover before clicking`);
    }

    if (isPhishing) {
        recommendations.push('🎯 **Phishing Confirmed**: This matches known phishing patterns - treat as malicious');
    }

    return recommendations;
}

// Update scan count
function updateScanCount(increment = true, isThreat = false) {
    chrome.storage.local.get(['scanCount', 'threatCount'], (data) => {
        let newScanCount = data.scanCount || 0;
        let newThreatCount = data.threatCount || 0;

        if (increment) {
            newScanCount++;
            if (isThreat) {
                newThreatCount++;
            }
        }

        chrome.storage.local.set({
            scanCount: newScanCount,
            threatCount: newThreatCount,
            lastAnalysis: JSON.stringify(currentAnalysis)
        }, () => {
            updateStats({ scanCount: newScanCount, threatCount: newThreatCount });
        });
    });
}

// Helper to escape HTML and prevent XSS
function escapeHTML(str) {
    if (!str === undefined || str === null) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Display analysis results
function displayAnalysisResults(results) {
    console.log('Displaying analysis results:', results);

    showView('analysisSection');

    analysisResults.innerHTML = buildDetailedResultsHTML(results);

    // Add to history
    addToHistory(results);

    // Add event listeners to result buttons
    setTimeout(() => {
        const saveBtn = document.getElementById('saveReportBtn');
        const copyBtn = document.getElementById('copyReportBtn');
        const exportBtn = document.getElementById('exportReportBtn');

        if (saveBtn) saveBtn.addEventListener('click', () => saveReport(results));
        if (copyBtn) copyBtn.addEventListener('click', () => copyReport(results));
        if (exportBtn) exportBtn.addEventListener('click', () => exportReport(results));
    }, 100);

    // Scroll to top
    analysisSection.scrollTop = 0;

    // Log analysis
    logAnalysis(results);
}

// Build detailed results HTML
function buildDetailedResultsHTML(results) {
    console.log('Building results with:', results);

    const riskColor = results.risk_level === 'HIGH' ? '#ef476f' :
        results.risk_level === 'MEDIUM' ? '#ff9e00' : '#06d6a0';

    const riskIcon = results.risk_level === 'HIGH' ? 'fas fa-exclamation-triangle' :
        results.risk_level === 'MEDIUM' ? 'fas fa-exclamation-circle' : 'fas fa-check-circle';

    const indicators = results.indicators || [];
    const warnings = results.warnings || [];
    const details = results.details || [];
    const technical = results.technical || [];
    const recommendations = results.recommendations || [];

    const indicatorCount = indicators.length;
    const warningCount = warnings.length;
    const detailCount = details.length;
    const techCount = technical.length;

    return `
        <!-- Summary Card -->
        <div class="card" style="border-left: 5px solid ${riskColor}; margin-bottom: 20px; animation: fadeIn 0.5s ease;">
            <div class="card-header" style="border-bottom: none;">
                <div class="card-icon" style="background: ${riskColor};">
                    <i class="${riskIcon}"></i>
                </div>
                <div style="flex: 1;">
                    <h2 class="card-title">Security Assessment Summary</h2>
                    <div style="font-size: 0.9rem; color: #6c757d; margin-top: 5px;">
                        Report ID: ${escapeHTML(results.report_id) || 'N/A'} • ${new Date(results.analysis_date).toLocaleString()}
                    </div>
                </div>
            </div>
            
            <!-- Risk Score -->
            <div class="risk-meter" style="margin: 20px 0; text-align: center;">
                <div class="risk-score risk-score-animation" style="font-size: 3.5rem; font-weight: 800; color: ${riskColor}; margin: 10px 0;">
                    ${results.risk_score || 0}<span style="font-size: 1.5rem; color: #6c757d;">/100</span>
                </div>
                <div class="risk-level" style="color: ${riskColor}; font-size: 1.3rem; font-weight: bold; margin: 10px 0;">
                    ${results.risk_level || 'MEDIUM'} RISK LEVEL
                </div>
                <div style="font-size: 0.9rem; color: #6c757d; margin-top: 10px;">
                    Confidence: ${results.confidence || '85%'} • Analyzed by: ${results.analyzed_by || 'Local Engine'}
                </div>
            </div>
            
            <!-- Quick Stats -->
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0;">
                <div style="padding: 15px; background: ${indicatorCount > 0 ? '#fff5f5' : '#f0f9ff'}; border-radius: 10px; text-align: center; border-left: 4px solid ${indicatorCount > 0 ? '#ff9e00' : '#4361ee'};">
                    <div style="font-size: 1.8rem; font-weight: bold; color: ${indicatorCount > 0 ? '#ff9e00' : '#4361ee'};">
                        ${indicatorCount}
                    </div>
                    <div style="font-size: 0.8rem; color: #6c757d; margin-top: 5px;">Indicators</div>
                </div>
                <div style="padding: 15px; background: ${warningCount > 0 ? '#fff5f5' : '#f0f9ff'}; border-radius: 10px; text-align: center; border-left: 4px solid ${warningCount > 0 ? '#ef476f' : '#4361ee'};">
                    <div style="font-size: 1.8rem; font-weight: bold; color: ${warningCount > 0 ? '#ef476f' : '#4361ee'};">
                        ${warningCount}
                    </div>
                    <div style="font-size: 0.8rem; color: #6c757d; margin-top: 5px;">Warnings</div>
                </div>
                <div style="padding: 15px; background: ${detailCount > 0 ? '#fff5f5' : '#f0f9ff'}; border-radius: 10px; text-align: center; border-left: 4px solid ${detailCount > 0 ? '#4361ee' : '#4361ee'};">
                    <div style="font-size: 1.8rem; font-weight: bold; color: ${detailCount > 0 ? '#4361ee' : '#4361ee'};">
                        ${detailCount}
                    </div>
                    <div style="font-size: 0.8rem; color: #6c757d; margin-top: 5px;">Details</div>
                </div>
                <div style="padding: 15px; background: #f0f9ff; border-radius: 10px; text-align: center; border-left: 4px solid #7209b7;">
                    <div style="font-size: 1.8rem; font-weight: bold; color: #7209b7;">
                        ${techCount}
                    </div>
                    <div style="font-size: 0.8rem; color: #6c757d; margin-top: 5px;">Technical</div>
                </div>
            </div>
            
            <!-- Status Indicators -->
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 20px 0;">
                <div style="padding: 15px; background: ${results.is_suspicious ? '#fff5f5' : '#f0f9ff'}; border-radius: 8px; border-left: 4px solid ${results.is_suspicious ? '#ef476f' : '#06d6a0'};">
                    <div style="font-size: 0.9rem; color: #6c757d; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-${results.is_suspicious ? 'exclamation-triangle' : 'check-circle'}" style="color: ${results.is_suspicious ? '#ef476f' : '#06d6a0'};"></i>
                        Suspicious
                    </div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: ${results.is_suspicious ? '#ef476f' : '#06d6a0'};">
                        ${results.is_suspicious ? 'YES ⚠️' : 'NO ✅'}
                    </div>
                </div>
                <div style="padding: 15px; background: ${results.is_phishing ? '#fff5f5' : '#f0f9ff'}; border-radius: 8px; border-left: 4px solid ${results.is_phishing ? '#ef476f' : '#06d6a0'};">
                    <div style="font-size: 0.9rem; color: #6c757d; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-${results.is_phishing ? 'fish' : 'shield-alt'}" style="color: ${results.is_phishing ? '#ef476f' : '#06d6a0'};"></i>
                        Phishing
                    </div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: ${results.is_phishing ? '#ef476f' : '#06d6a0'};">
                        ${results.is_phishing ? 'DETECTED 🎣' : 'CLEAN ✅'}
                    </div>
                </div>
                <div style="padding: 15px; background: ${results.is_spoofed ? '#fff5f5' : '#f0f9ff'}; border-radius: 8px; border-left: 4px solid ${results.is_spoofed ? '#ef476f' : '#06d6a0'};">
                    <div style="font-size: 0.9rem; color: #6c757d; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-${results.is_spoofed ? 'user-secret' : 'user-check'}" style="color: ${results.is_spoofed ? '#ef476f' : '#06d6a0'};"></i>
                        Spoofed
                    </div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: ${results.is_spoofed ? '#ef476f' : '#06d6a0'};">
                        ${results.is_spoofed ? 'YES 👤' : 'NO ✅'}
                    </div>
                </div>
                <div style="padding: 15px; background: #f0f9ff; border-radius: 8px; border-left: 4px solid #4361ee;">
                    <div style="font-size: 0.9rem; color: #6c757d; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-cogs" style="color: #4361ee;"></i>
                        Engine
                    </div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: #4361ee;">
                        ${results.analyzed_by || 'Local'}
                    </div>
                </div>
            </div>
            
            <!-- Email Info -->
            ${results.subject || results.from ? `
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 10px; border: 1px solid #e9ecef;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        ${results.subject ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Subject</div>
                                <div style="font-weight: 600; color: #333; word-break: break-word;">${escapeHTML(results.subject)}</div>
                            </div>
                        ` : ''}
                        ${results.from ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Sender</div>
                                <div style="font-weight: 600; color: #333; word-break: break-word;">${escapeHTML(results.from)}</div>
                            </div>
                        ` : ''}
                        ${results.senderDomain ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Domain</div>
                                <div style="font-weight: 600; color: #333;">${escapeHTML(results.senderDomain)}</div>
                            </div>
                        ` : ''}
                        ${results.totalUrls !== undefined ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Links</div>
                                <div style="font-weight: 600; color: ${results.totalUrls > 0 ? '#ef476f' : '#06d6a0'};">${escapeHTML(results.totalUrls)} (${escapeHTML(results.suspiciousUrls) || 0} suspicious)</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            ` : ''}
        </div>
        
        <!-- Indicators Section -->
        ${indicatorCount > 0 ? `
            <div class="card" style="margin-bottom: 20px; animation: fadeIn 0.6s ease;">
                <div class="card-header">
                    <div class="card-icon" style="background: linear-gradient(135deg, #ff9e00, #ff6b6b);">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <h2 class="card-title">Detected Security Indicators (${indicatorCount})</h2>
                </div>
                <div class="result-content" style="padding: 0 20px 20px;">
                    <p style="color: #6c757d; margin-bottom: 15px; font-size: 0.9rem;">
                        These indicators suggest potential security issues with this email:
                    </p>
                    ${indicators.map((ind, index) => `
                        <div style="display: flex; align-items: flex-start; gap: 12px; padding: 15px; margin: 10px 0; background: #fff5f5; border-radius: 10px; border-left: 4px solid #ff9e00; animation: fadeIn 0.${index + 3}s ease;">
                            <div style="width: 24px; height: 24px; background: #ff9e00; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; font-size: 0.8rem;">
                                ${index + 1}
                            </div>
                            <div style="flex: 1;">
                                <div style="font-weight: 600; color: #333; margin-bottom: 5px;">
                                    ${escapeHTML(ind)}
                                </div>
                                <div style="font-size: 0.8rem; color: #666;">
                                    <i class="fas fa-info-circle" style="margin-right: 5px;"></i>
                                    Security indicator requiring attention
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
        
        <!-- Warnings Section -->
        ${warningCount > 0 ? `
            <div class="card" style="margin-bottom: 20px; animation: fadeIn 0.7s ease;">
                <div class="card-header">
                    <div class="card-icon" style="background: linear-gradient(135deg, #ef476f, #ff0054);">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <h2 class="card-title">Security Warnings (${warningCount})</h2>
                </div>
                <div class="result-content" style="padding: 0 20px 20px;">
                    <p style="color: #6c757d; margin-bottom: 15px; font-size: 0.9rem;">
                        These warnings require immediate attention:
                    </p>
                    ${warnings.map((warn, index) => `
                        <div style="display: flex; align-items: flex-start; gap: 12px; padding: 15px; margin: 10px 0; background: #fff5f5; border-radius: 10px; border-left: 4px solid #ef476f; animation: fadeIn 0.${index + 4}s ease;">
                            <div style="width: 24px; height: 24px; background: #ef476f; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; font-size: 0.8rem;">
                                ${index + 1}
                            </div>
                            <div style="flex: 1;">
                                <div style="font-weight: 600; color: #333; margin-bottom: 5px;">
                                    ⚠️ ${escapeHTML(warn)}
                                </div>
                                <div style="font-size: 0.8rem; color: #666;">
                                    <i class="fas fa-skull-crossbones" style="margin-right: 5px;"></i>
                                    High priority - requires immediate action
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
        
        <!-- Details Section -->
        ${detailCount > 0 ? `
            <div class="card" style="margin-bottom: 20px; animation: fadeIn 0.8s ease;">
                <div class="card-header">
                    <div class="card-icon" style="background: linear-gradient(135deg, #4361ee, #3a0ca3);">
                        <i class="fas fa-search"></i>
                    </div>
                    <h2 class="card-title">Detailed Analysis (${detailCount})</h2>
                </div>
                <div class="result-content" style="padding: 0 20px 20px;">
                    <p style="color: #6c757d; margin-bottom: 15px; font-size: 0.9rem;">
                        Specific findings from the email analysis:
                    </p>
                    ${details.map((detail, index) => {
        const severityColor = detail.severity === 'high' ? '#ef476f' :
            detail.severity === 'medium' ? '#ff9e00' : '#4361ee';
        return `
                        <div style="padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 10px; border: 1px solid #e9ecef; border-left: 4px solid ${severityColor}; animation: fadeIn 0.${index + 5}s ease;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                                <div style="width: 24px; height: 24px; background: ${severityColor}; color: white; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: bold;">
                                    ${index + 1}
                                </div>
                                <div style="font-weight: 600; color: #333; flex: 1;">
                                    ${escapeHTML(detail.title) || 'Finding'}
                                </div>
                                <div style="font-size: 0.7rem; padding: 2px 8px; background: ${severityColor}; color: white; border-radius: 10px; font-weight: 600;">
                                    ${(detail.severity || 'info').toUpperCase()}
                                </div>
                            </div>
                            <div style="color: #666; font-size: 0.9rem; margin-left: 34px;">
                                ${escapeHTML(detail.description) || escapeHTML(JSON.stringify(detail))}
                            </div>
                            ${detail.type ? `
                                <div style="font-size: 0.7rem; color: #999; margin-top: 8px; margin-left: 34px;">
                                    <i class="fas fa-tag" style="margin-right: 5px;"></i>
                                    ${escapeHTML(detail.type)}
                                </div>
                            ` : ''}
                        </div>
                    `}).join('')}
                </div>
            </div>
        ` : ''}
        
        <!-- Technical Details -->
        ${techCount > 0 ? `
            <div class="card" style="margin-bottom: 20px; animation: fadeIn 0.9s ease;">
                <div class="card-header">
                    <div class="card-icon" style="background: linear-gradient(135deg, #7209b7, #f72585);">
                        <i class="fas fa-code"></i>
                    </div>
                    <h2 class="card-title">Technical Analysis (${techCount})</h2>
                </div>
                <div class="result-content" style="padding: 20px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        ${technical.map((tech, index) => `
                            <div style="padding: 12px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e9ecef;">
                                <div style="font-size: 0.8rem; color: #6c757d; margin-bottom: 5px;">
                                    <i class="fas fa-circle" style="font-size: 0.5rem; margin-right: 8px; color: #7209b7;"></i>
                                    Technical Detail ${index + 1}
                                </div>
                                <div style="font-weight: 600; color: #333;">${escapeHTML(tech)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        ` : ''}
        
        <!-- Recommendations -->
        <div class="card" style="margin-bottom: 20px; animation: fadeIn 1s ease;">
            <div class="card-header">
                <div class="card-icon" style="background: linear-gradient(135deg, #06d6a0, #118ab2);">
                    <i class="fas fa-lightbulb"></i>
                </div>
                <h2 class="card-title">Action Recommendations</h2>
            </div>
            <div class="result-content" style="padding: 0 20px 20px;">
                <p style="color: #6c757d; margin-bottom: 15px; font-size: 0.9rem;">
                    Based on the analysis results, here are the recommended actions (in order of priority):
                </p>
                ${recommendations.map((rec, index) => `
                    <div style="display: flex; align-items: flex-start; gap: 15px; padding: 15px; margin: 10px 0; background: ${index === 0 && results.risk_level === 'HIGH' ? '#fff5f5' : '#f8f9fa'}; border-radius: 10px; border-left: 4px solid ${index === 0 && results.risk_level === 'HIGH' ? '#ef476f' : '#06d6a0'}; animation: fadeIn 0.${index + 6}s ease;">
                        <div style="width: 30px; height: 30px; background: ${index === 0 && results.risk_level === 'HIGH' ? '#ef476f' : '#06d6a0'}; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0;">
                            ${index + 1}
                        </div>
                        <div style="flex: 1; font-weight: 500; color: #333;">
                            ${rec}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        
        <!-- Action Buttons -->
        <div class="card" style="animation: fadeIn 1.1s ease;">
            <div class="card-header">
                <div class="card-icon" style="background: linear-gradient(135deg, #3a0ca3, #4361ee);">
                    <i class="fas fa-download"></i>
                </div>
                <h2 class="card-title">Export & Save Report</h2>
            </div>
            <div class="result-content" style="padding: 20px; text-align: center;">
                <p style="color: #6c757d; margin-bottom: 20px; font-size: 0.9rem;">
                    Save this report for future reference or share with your security team.
                </p>
                <div style="display: flex; gap: 15px; justify-content: center; flex-wrap: wrap;">
                    <button class="btn btn-primary" id="saveReportBtn" style="flex: 1; min-width: 150px;">
                        <i class="fas fa-save"></i> Save to Browser
                    </button>
                    <button class="btn btn-secondary" id="copyReportBtn" style="flex: 1; min-width: 150px;">
                        <i class="fas fa-copy"></i> Copy Summary
                    </button>
                    <button class="btn btn-secondary" id="exportReportBtn" style="flex: 1; min-width: 150px;">
                        <i class="fas fa-file-pdf"></i> Export as PDF
                    </button>
                </div>
            </div>
        </div>
    `;
}

// Add to history
function addToHistory(results) {
    analysisHistory.unshift({
        ...results,
        savedAt: new Date().toISOString()
    });

    // Keep only last 20 reports
    if (analysisHistory.length > 20) {
        analysisHistory = analysisHistory.slice(0, 20);
    }

    chrome.storage.local.set({
        savedReports: analysisHistory,
        lastAnalysis: JSON.stringify(results)
    });

    // Sync local reports to server if linked
    if (results.analyzed_by && results.analyzed_by.includes('Local')) {
        syncReportToServer(results);
    }
}

// Sync report to server
async function syncReportToServer(results) {
    if (!isLinked || !extensionToken) return;

    console.log('Syncing local report to server...');

    try {
        const response = await fetch(`${API_BASE_URL}/extension/reports/sync`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${extensionToken}`,
                'x-extension-key': (userInfo || {}).apiKey
            },
            body: JSON.stringify({
                subject: results.subject || 'No Subject',
                sender: results.from || 'Unknown Sender',
                content: emailInput.value || '',
                riskLevel: (results.risk_level || 'low').toLowerCase(),
                riskScore: results.risk_score || 0,
                status: results.is_phishing ? 'malicious' : (results.is_suspicious ? 'suspicious' : 'safe'),
                threats: [...(results.indicators || []), ...(results.warnings || [])],
                details: {
                    details: results.details,
                    technical: results.technical,
                    recommendations: results.recommendations
                },
                analysisTime: results.analysisTime || 0
            })
        });

        const data = await response.json();
        if (data.success) {
            console.log('✅ Local report synced to server');
        } else {
            console.error('❌ Sync failed:', data.message);
        }
    } catch (e) {
        console.error('❌ Failed to sync report:', e);
    }
}

// Show reports
function showReports() {
    if (analysisHistory.length === 0) {
        showNotification('No saved reports found', 'info');
        return;
    }

    const reportsHTML = analysisHistory.map((report, index) => `
        <div style="padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 10px; border-left: 4px solid ${report.risk_level === 'HIGH' ? '#ef476f' : report.risk_level === 'MEDIUM' ? '#ff9e00' : '#06d6a0'}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-weight: 600; color: #333;">${escapeHTML(report.subject) || 'Unknown Subject'}</div>
                    <div style="font-size: 0.8rem; color: #6c757d;">${new Date(report.savedAt || report.analysis_date).toLocaleString()}</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 1.5rem; font-weight: 700; color: ${report.risk_level === 'HIGH' ? '#ef476f' : report.risk_level === 'MEDIUM' ? '#ff9e00' : '#06d6a0'}">
                        ${escapeHTML(report.risk_score)}
                    </div>
                    <div style="font-size: 0.7rem; color: #6c757d;">${escapeHTML(report.risk_level)} risk</div>
                </div>
            </div>
        </div>
    `).join('');

    const popup = document.createElement('div');
    popup.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;">
            <div style="background: white; padding: 30px; border-radius: 20px; max-width: 600px; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.3);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 style="color: #212529; margin: 0;">Saved Reports (${analysisHistory.length})</h3>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" style="background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #6c757d;">×</button>
                </div>
                ${reportsHTML}
                <div style="margin-top: 20px; text-align: center;">
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" style="background: linear-gradient(135deg, #4361ee, #7209b7); color: white; border: none; padding: 12px 30px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: all 0.3s;">
                        Close
                    </button>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(popup);
}

// Show feature popup
function showFeaturePopup(message, icon = '🚀') {
    const popup = document.createElement('div');
    popup.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;">
            <div style="background: white; padding: 30px; border-radius: 20px; max-width: 400px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.3);">
                <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #4361ee, #7209b7); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; color: white; font-size: 30px;">
                    ${icon}
                </div>
                <h3 style="color: #212529; margin-bottom: 15px;">Coming Soon!</h3>
                <p style="color: #6c757d; line-height: 1.6; margin-bottom: 25px;">${message}</p>
                <button onclick="this.parentElement.parentElement.remove()" style="background: linear-gradient(135deg, #4361ee, #7209b7); color: white; border: none; padding: 12px 30px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: all 0.3s;">
                    Got it!
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(popup);

    // Auto-close after 5 seconds
    setTimeout(() => {
        if (popup.parentNode) {
            popup.remove();
        }
    }, 5000);
}

// Utility functions
function showLoading(show, title = 'Analyzing Email', subtitle = 'Please wait...') {
    loadingOverlay.style.display = show ? 'flex' : 'none';
    if (show) {
        loadingText.textContent = title;
        loadingSubtext.textContent = subtitle;
        progressFill.style.width = '0%';
    }
}

function clearInput() {
    emailInput.value = '';
    chrome.storage.local.remove(['currentEmail']);
    showNotification('Input cleared successfully', 'success');
    updateStatus('Ready to analyze');
    emailInput.focus();
}

function goBack() {
    showView('inputSection');
    updateStatus('Ready for new analysis');
    emailInput.focus();
}

function updateStatus(message) {
    statusText.textContent = message;
}

function showNotification(message, type = 'info') {
    const colors = {
        success: '#06d6a0',
        error: '#ef476f',
        warning: '#ff9e00',
        info: '#4361ee'
    };

    const icons = {
        success: 'check-circle',
        error: 'times-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };

    const notification = document.createElement('div');
    notification.innerHTML = `
        <div style="position: fixed; top: 20px; right: 20px; padding: 15px 25px; background: ${colors[type]}; color: white; border-radius: 12px; z-index: 10000; display: flex; align-items: center; gap: 12px; box-shadow: 0 8px 25px rgba(0,0,0,0.15); animation: slideIn 0.3s ease;">
            <i class="fas fa-${icons[type]}" style="font-size: 1.2rem;"></i>
            <span style="font-weight: 500;">${message}</span>
        </div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }
    }, 3000);
}

// Report functions
function saveReport(results = currentAnalysis) {
    if (!results) {
        showNotification('No analysis to save', 'error');
        return;
    }

    chrome.storage.local.get(['savedReports'], (data) => {
        const reports = data.savedReports || [];
        reports.unshift({
            ...results,
            savedAt: new Date().toISOString()
        });

        // Keep only last 50 reports
        const limitedReports = reports.slice(0, 50);

        chrome.storage.local.set({ savedReports: limitedReports }, () => {
            showNotification('✅ Report saved to browser storage', 'success');
            analysisHistory = limitedReports;
        });
    });
}

function copyReport(results = currentAnalysis) {
    if (!results) {
        showNotification('No analysis to copy', 'error');
        return;
    }

    const summary = `
📋 Email Forensic Analysis Report
${'═'.repeat(40)}

📊 RISK ASSESSMENT
• Risk Score: ${results.risk_score}/100
• Risk Level: ${results.risk_level}
• Confidence: ${results.confidence}
• Analyzed: ${new Date(results.analysis_date).toLocaleString()}

🚨 SECURITY STATUS
• Suspicious: ${results.is_suspicious ? 'YES ⚠️' : 'NO ✅'}
• Phishing: ${results.is_phishing ? 'DETECTED 🎣' : 'CLEAN ✅'}
• Spoofed: ${results.is_spoofed ? 'YES 👤' : 'NO ✅'}

📧 EMAIL INFORMATION
• Subject: ${results.subject || 'N/A'}
• Sender: ${results.from || 'N/A'}
• Domain: ${results.senderDomain || 'N/A'}
• Links: ${results.totalUrls || 0} (${results.suspiciousUrls || 0} suspicious)

🔍 DETECTED INDICATORS
${results.indicators && results.indicators.length > 0 ?
            results.indicators.map((ind, i) => `  ${i + 1}. ${ind}`).join('\n') :
            '  No indicators detected'}

⚠️ SECURITY WARNINGS
${results.warnings && results.warnings.length > 0 ?
            results.warnings.map((warn, i) => `  ${i + 1}. ⚠️ ${warn}`).join('\n') :
            '  No warnings'}

✅ RECOMMENDED ACTIONS
${results.recommendations && results.recommendations.length > 0 ?
            results.recommendations.slice(0, 5).map((rec, i) => `  ${i + 1}. ${rec.replace(/\*\*/g, '')}`).join('\n') :
            '  No specific recommendations'}

📋 REPORT METADATA
• Report ID: ${results.report_id}
• Analysis Engine: ${results.analyzed_by}
• Features Checked: ${results.features_checked || 'N/A'}
• Total Findings: ${(results.indicators || []).length + (results.warnings || []).length}

${'═'.repeat(40)}
Generated by Email Forensic Analyzer
${new Date().toLocaleString()}
    `.trim();

    navigator.clipboard.writeText(summary)
        .then(() => showNotification('✅ Summary copied to clipboard', 'success'))
        .catch(err => {
            console.error('Copy failed:', err);
            showNotification('Failed to copy: ' + err.message, 'error');
        });
}

function exportReport(results = currentAnalysis) {
    if (!results) {
        showNotification('No analysis to export', 'error');
        return;
    }

    const dataStr = JSON.stringify(results, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

    const exportFileDefaultName = `email-analysis-${results.report_id || Date.now()}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    document.body.appendChild(linkElement);
    linkElement.click();
    document.body.removeChild(linkElement);

    showNotification('✅ Report exported as JSON', 'success');
}

// Check for recently fetched email
function checkForRecentEmail() {
    chrome.storage.local.get(['lastFetched', 'lastEmailSubject'], (result) => {
        if (result.lastFetched && result.lastEmailSubject) {
            const lastFetched = new Date(result.lastFetched);
            const now = new Date();
            const diffMinutes = (now - lastFetched) / (1000 * 60);

            if (diffMinutes < 5) {
                updateStatus(`Recent email: ${result.lastEmailSubject.substring(0, 30)}...`);
            }
        }
    });
}

// Log analysis for debugging
function logAnalysis(results) {
    console.log('📊 Analysis completed:', {
        risk_score: results.risk_score,
        risk_level: results.risk_level,
        suspicious: results.is_suspicious,
        phishing: results.is_phishing,
        indicators: results.indicators?.length || 0,
        warnings: results.warnings?.length || 0
    });
}

// Initialize on load
document.addEventListener('DOMContentLoaded', init);

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        analyzeLocally,
        formatEmailPreview,
        showNotification
    };
}