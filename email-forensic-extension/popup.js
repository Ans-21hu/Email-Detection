const API_BASE_URL = 'https://mailxpose.tech/api/api';

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
const logoutBtn = document.getElementById('logoutBtn');
const profileToggle = document.getElementById('profileToggle');
const profileDropdown = document.getElementById('profileDropdown');
const profileContainer = document.getElementById('profileContainer');
const userNameDisplay = document.getElementById('userNameDisplay');
const userEmailDisplay = document.getElementById('userEmailDisplay');


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

    // Check for daily reset
    checkDailyReset();

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

    // Proactively sync subscription/profile from server on startup
    reauthenticate().then(() => {
        console.log('🔄 Profile synced from server');
        checkDashboardConnection();
    });

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
            el.style.display = (id === viewId) ? 'flex' : 'none';
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
    if (!data) return;

    const scans = data.scanCount || 0;
    const threats = data.threatCount || 0;
    const successPercentage = scans > 0 ? Math.round(((scans - threats) / scans) * 100) : 100;

    // Animate count
    animateCount('scanCount', scans);
    const scanCount2 = document.getElementById('scanCount2');
    if (scanCount2) {
        animateCount('scanCount2', scans);
    }
    animateCount('threatCount', threats);

    // Safety checks for DOM elements
    if (document.getElementById('successRate')) {
        document.getElementById('successRate').textContent = `${successPercentage}%`;
    }
    if (document.getElementById('emailCount')) {
        document.getElementById('emailCount').textContent = `${scans} emails analyzed`;
    }

    // Update threat count color
    const threatEl = document.getElementById('threatCount');
    if (threatEl && threats > 0) {
        threatEl.style.color = 'var(--danger)';
        threatEl.style.fontWeight = 'bold';
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

    // Logout Button
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
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

    // PDF Export listener (delegated since button is dynamic)
    document.addEventListener('click', (e) => {
        if (e.target && (e.target.id === 'exportPdfBtn' || e.target.closest('#exportPdfBtn'))) {
            exportReportAsPDF();
        }
    });

    // Dropdown toggles
    if (profileToggle) {
        profileToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            profileDropdown.classList.toggle('active');
        });
    }

    // Close dropdowns when clicking outside
    document.addEventListener('click', () => {
        if (profileDropdown) profileDropdown.classList.remove('active');
    });

    if (profileDropdown) {
        profileDropdown.addEventListener('click', (e) => e.stopPropagation());
    }

    // Navigation links in dropdown
    const navDashboard = document.getElementById('navDashboard');
    if (navDashboard) {
        navDashboard.addEventListener('click', () => {
            window.open('https://mailxpose.tech/dashboard.html', '_blank');
        });
    }


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
        // 0. Check Usage Limits BEFORE starting
        const data = await storage.get(['subscriptionPlan', 'scanCount', 'lastResetDate']);
        const plan = data.subscriptionPlan || 'Free';
        const scanCount = data.scanCount || 0;

        // Normalize Plan and Limits
        const getPlanLimit = (p) => {
            const pStr = String(p).toLowerCase();
            if (pStr.includes('199') || pStr.includes('elite')) return 50;
            if (pStr.includes('99') || pStr.includes('pro')) return 15;
            return 3;
        };

        const dailyLimit = getPlanLimit(plan);

        if (scanCount >= dailyLimit) {
            showLoading(false);
            showNotification('❌ Daily limit exceeded! Please upgrade.', 'error');
            updateStatus('Daily limit reached');

            showFeaturePopup(`
                <h3 style="margin-bottom: 10px; color: #ef4444;">Daily Limit Reached</h3>
                <p>You have used all <b>${dailyLimit}</b> scans for your <b>${plan} Plan</b>.</p>
                <p>Upgrade to Pro for more daily analyses!</p>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 12px; margin-top: 20px;">
                    <button id="viewPlansBtn" 
                        style="background: linear-gradient(135deg, #0ff0fc, #ff00ff); color: white; border: none; padding: 12px 30px; border-radius: 25px; font-weight: bold; cursor: pointer; width: 80%; box-shadow: 0 4px 15px rgba(15, 240, 252, 0.3);">
                        View Plans
                    </button>
                    <button id="closePopupBtn" style="background: rgba(255,255,255,0.05); color: var(--text-dim); border: 1px solid rgba(255,255,255,0.1); padding: 8px 20px; border-radius: 20px; cursor: pointer; font-size: 0.85rem;">
                        Maybe Later
                    </button>
                </div>
            `, '🛑');

            setTimeout(() => {
                const closeBtn = document.getElementById('closePopupBtn');
                if (closeBtn) closeBtn.onclick = () => {
                    const popup = document.querySelector('.feature-popup-overlay');
                    if (popup) popup.remove();
                };

                const viewPlansBtn = document.getElementById('viewPlansBtn');
                if (viewPlansBtn) {
                    viewPlansBtn.onclick = () => {
                        window.open('https://mailxpose.tech/dashboard.html#subscription', '_blank');
                        const popup = document.querySelector('.feature-popup-overlay');
                        if (popup) popup.remove();
                    };
                }
            }, 100);

            return;
        }

        // 1. Try backend API (Priority for 95%+ accuracy)
        updateStatus('Connecting to AI Engine...');
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
            throw new Error('Backend failed to process');
        }

    } catch (error) {
        console.error('Analysis error:', error);

        // Fallback to local analysis if backend fails (unless it's a limit error)
        if (error.isLimitExceeded || error.message.includes('Usage limit exceeded')) {
            showLoading(false);
            showNotification('❌ Daily limit exceeded! Please upgrade.', 'error');
            updateStatus('Daily limit reached');
            return;
        }

        updateStatus('Fallback to local engine...');
        analyzeLocally(emailContent).then(localResult => {
            currentAnalysis = localResult;
            showLoading(false);
            displayAnalysisResults(localResult);
            updateStatus('Analysis complete (Local Fallback)');
            showNotification('✅ Analysis completed in Offline Mode', 'success');

            // Update scan count
            updateScanCount(true, localResult.is_suspicious || localResult.is_phishing);
        }).catch(err => {
            console.error('Local analysis error:', err);
            showLoading(false);
            showNotification('❌ Analysis failed.', 'error');
        });
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

        // Get DOM-extracted links from storage
        let extractedLinks = [];
        try {
            const data = await new Promise(res => chrome.storage.local.get(['currentEmail'], d => res(d)));
            if (data.currentEmail) {
                const parsed = JSON.parse(data.currentEmail);
                if (Array.isArray(parsed.extractedLinks)) extractedLinks = parsed.extractedLinks;
            }
        } catch (e) { console.error('Error getting extracted links:', e); }

        const requestBody = {
            content: emailContent,
            subject: subject,
            sender: sender,
            source: 'extension',
            extractedLinks: extractedLinks,
            apiKey: (userInfo || {}).apiKey
        };

        const response = await fetch(`${API_BASE_URL}/analysis/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${extensionToken}`
            },
            body: JSON.stringify(requestBody),
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
                    'Authorization': `Bearer ${extensionToken}`
                },
                body: JSON.stringify(requestBody)
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

        const backendResult = transformBackendResult(await response.json());

        // Extract URLs locally to ensure we have them for the UI
        const urls = extractUrls(emailContent);
        const suspiciousUrls = urls.filter(isSuspiciousUrl);

        // Merge URL data into result
        backendResult.urls = urls;
        backendResult.suspiciousUrls = suspiciousUrls;
        backendResult.totalUrls = urls.length;

        // Add Local Technical Details to the result
        // The UI expects an array of strings in 'technical'
        backendResult.technical = [
            ...(backendResult.technical || []),
            `Total URLs found: ${urls.length}`,
            `Suspicious URLs: ${suspiciousUrls.length}`,
            `Secure (HTTPS) URLs: ${urls.filter(url => url.startsWith('https://')).length}`
        ];

        return backendResult;

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

    // Helper map for better descriptions of backend codes
    const descriptionMap = {
        'suspicious_keyword_security': 'Found "security" keyword. Scammers often use security alerts to trigger panic.',
        'suspicious_keyword_google': 'Found "google" keyword. Brand impersonation is common in phishing.',
        'malicious_keyword_hack': 'Found "hack" keyword. Explicit threat terminology detected.',
        'contains_links': 'Email contains links. Verify destinations before clicking.'
    };

    // If details are empty but we have indicators/warnings, populate them for the UI
    if (detailedFindings.length === 0) {
        indicatorsArr.forEach(ind => {
            if (typeof ind === 'string') {
                // Try to get a better description or formatted string
                let cleanDesc = ind.replace(/_/g, ' ');
                // If it looks like a code (no spaces), try to format it
                if (!cleanDesc.includes(' ')) {
                    cleanDesc = cleanDesc.charAt(0).toUpperCase() + cleanDesc.slice(1);
                }

                // Specific overwrites
                if (ind.includes('suspicious_keyword')) {
                    const keyword = ind.split('_').pop();
                    cleanDesc = `Found suspicious keyword: "${keyword}". potentially used for social engineering.`;
                }

                detailedFindings.push({
                    type: 'indicator',
                    title: 'Security Indicator',
                    description: descriptionMap[ind] || cleanDesc,
                    severity: 'medium'
                });
            } else if (typeof ind === 'object') {
                detailedFindings.push(ind);
            }
        });

        warningsArr.forEach(warn => {
            if (typeof warn === 'string') {
                let cleanDesc = descriptionMap[warn];

                if (!cleanDesc) {
                    cleanDesc = warn.replace(/_/g, ' ');
                    if (warn.includes('suspicious_keyword')) {
                        const keyword = warn.split('_').pop();
                        cleanDesc = `High-risk keyword "${keyword}" detected. Exercise caution.`;
                    }
                }

                detailedFindings.push({
                    type: 'warning',
                    title: 'Security Warning',
                    description: cleanDesc || warn,
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
        confidence: data.confidence || '98%+',
        subject: data.subject,
        from: data.sender || data.from
    };
}

// Helper for promisified storage
const storage = {
    get: (keys) => new Promise((resolve) => chrome.storage.local.get(keys, resolve)),
    set: (items) => new Promise((resolve) => chrome.storage.local.set(items, resolve))
};

// Handle Dashboard Linking
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
        const loginUrl = `${API_BASE_URL}/auth/login`;
        console.log('🔐 Attempting login to:', loginUrl);

        const loginResponse = await fetch(loginUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        console.log('📥 Login response status:', loginResponse.status);
        const loginData = await loginResponse.json();
        console.log('📦 Login data:', loginData);

        if (!loginData.success) {
            console.error('❌ Login failed details:', JSON.stringify(loginData, null, 2));
            throw new Error(loginData.message || 'Login failed - Check credentials');
        }

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
        const registerUrl = `${API_BASE_URL}/extension/register`;
        console.log('📝 Attempting extension registration to:', registerUrl);
        console.log('📤 Registration payload:', { userId, extensionId, subscriptionPlan: subPlan });

        const registerResponse = await fetch(registerUrl, {
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
            const retryResponse = await fetch(registerUrl, {
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
            subscriptionPlan: subPlan || 'Free',
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

        // Improve error message for user
        let cleanMsg = error.message;
        if (cleanMsg.includes('Failed to fetch')) {
            cleanMsg = 'Cannot connect to server. Check internet connection.';
        } else if (cleanMsg.includes('401') || cleanMsg.includes('403')) {
            cleanMsg = 'Invalid email or password.';
        }

        showNotification('Connection failed: ' + cleanMsg, 'error');
        linkDashboardBtn.textContent = 'Login';
        linkDashboardBtn.disabled = false;
        updateStatus('Connection failed');
    }
}

// Handle Logout
async function handleLogout() {
    if (!confirm('Are you sure you want to logout? This will clear your extension stats.')) {
        return;
    }

    updateStatus('Logging out...');

    try {
        // Use background script to clear everything safely
        chrome.runtime.sendMessage({ action: 'logout' }, (response) => {
            if (response && response.success) {
                showNotification('✅ Logged out successfully', 'success');
                // Storage listener will trigger UI update
            } else {
                // Fallback: Clear manually if message fails
                chrome.storage.local.remove([
                    'apiKey', 'extensionId', 'userId', 'linkedEmail', 'isLinked',
                    'extensionToken', 'userInfo', 'scanCount', 'threatCount'
                ], () => {
                    checkDashboardConnection();
                });
            }
        });
    } catch (e) {
        console.error('Logout error:', e);
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
                if (result.user && result.user.subscriptionPlan) {
                    await storage.set({ subscriptionPlan: result.user.subscriptionPlan });
                }
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
        // Show profile container
        if (profileContainer) profileContainer.style.display = 'block';

        // Update profile info
        if (userEmailDisplay) userEmailDisplay.textContent = data.linkedEmail || 'Connected';
        if (userNameDisplay) {
            // Try to get name from storage or use email prefix
            chrome.storage.local.get(['userName'], (res) => {
                userNameDisplay.textContent = res.userName || (data.linkedEmail ? data.linkedEmail.split('@')[0] : 'User');
            });
        }

        // Only switch to input view if we just linked or if we were on the setup page
        if (!previousLinkedState || currentVisibleView === 'setupSection' || !currentVisibleView) {
            showView('inputSection');
        }

        // Update subscription UI
        updateSubscriptionUI();

    } else {
        // Hide profile container
        if (profileContainer) profileContainer.style.display = 'none';

        // Hide subscription elements
        const planDisplay = document.getElementById('planDisplay');
        const usageContainer = document.getElementById('usageContainer');
        if (planDisplay) planDisplay.style.display = 'none';
        if (usageContainer) usageContainer.style.display = 'none';

        isLinked = false;
        showView('setupSection');
    }
}

// Update Subscription UI
async function updateSubscriptionUI() {
    const data = await storage.get(['subscriptionPlan', 'scanCount', 'lastResetDate']);
    const plan = data.subscriptionPlan || 'Free';
    const scanCount = data.scanCount || 0;

    // Limits Mapping
    const getPlanInfo = (p) => {
        const pStr = String(p).toLowerCase();
        if (pStr.includes('199') || pStr.includes('elite')) return { limit: 50, name: 'Elite' };
        if (pStr.includes('99') || pStr.includes('pro')) return { limit: 15, name: 'Pro' };
        return { limit: 3, name: 'Free' };
    };

    const planInfo = getPlanInfo(plan);
    const dailyLimit = planInfo.limit;
    const remaining = Math.max(0, dailyLimit - scanCount);
    const progress = Math.min(100, (scanCount / dailyLimit) * 100);

    // Update Banner Badge
    const planDisplay = document.getElementById('planDisplay');
    if (planDisplay) {
        planDisplay.textContent = `${planInfo.name} Plan`;
        planDisplay.style.display = 'inline-block';
        planDisplay.className = 'subscription-badge ' +
            (planInfo.name === 'Free' ? 'plan-free' : (planInfo.name === 'Pro' ? 'plan-99' : 'plan-199'));
    }

    // Set plan badge correctly even if name doesn't match exactly
    if (planInfo.name === 'Pro') planDisplay.classList.add('plan-99');
    if (planInfo.name === 'Elite') planDisplay.classList.add('plan-199');

    // Update Usage Section
    const usageContainer = document.getElementById('usageContainer');
    const usageValue = document.getElementById('usageValue');
    const usageFill = document.getElementById('usageFill');
    const limitNotice = document.getElementById('limitNotice');

    if (usageContainer) {
        usageContainer.style.display = 'block';
        if (usageValue) usageValue.textContent = `${scanCount} / ${dailyLimit}`;
        if (usageFill) usageFill.style.width = `${progress}%`;

        if (limitNotice) {
            if (remaining <= 0) {
                limitNotice.innerHTML = '🚨 <span style="color: #ff0055; font-weight: bold;">Daily limit reached!</span> Upgrade for more scans.';
            } else if (remaining <= 2) {
                limitNotice.innerHTML = '⚠️ <span style="color: #ffd800;">Only ' + remaining + ' scans left today.</span>';
            } else {
                limitNotice.textContent = 'You have ' + remaining + ' scans remaining for today.';
            }
        }
    }
}

// Local analysis
async function analyzeLocally(emailContent) {
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
    const suspiciousUrls = urls.filter(isSuspiciousUrl);

    // 1. Check for phishing keywords
    const keywordCategories = {
        urgency: ['urgent', 'immediately', 'verify', 'confirm', 'action required', 'update now'],
        sensitive: ['password', 'login', 'account', 'security', 'secure your account', 'new device', 'unusual activity'],
        financial: ['payment', 'invoice', 'overdue', 'bank', 'wire transfer', 'suspended', 'limited'],
        generic: ['click here', 'login detected']
    };

    let totalKeywords = 0;

    // Check each category
    Object.entries(keywordCategories).forEach(([category, keywords]) => {
        const found = keywords.filter(k => lowerContent.includes(k));
        if (found.length > 0) {
            totalKeywords += found.length;
            riskScore += found.length * 8;

            // Educational descriptions based on category
            let desc = '';
            if (category === 'urgency') desc = 'Scammers use urgency to make you act without thinking.';
            if (category === 'sensitive') desc = 'Requests for credentials or security checks are common in phishing.';
            if (category === 'financial') desc = 'Financial threats often use fake invoices or suspension warnings.';
            if (category === 'generic') desc = 'Generic CTA buttons or links are often malicious.';

            details.push({
                type: 'keyword',
                title: `${category.charAt(0).toUpperCase() + category.slice(1)} Keywords Detected`,
                description: `Found "${found.join(', ')}". ${desc}`,
                severity: 'medium'
            });
        }
    });

    if (totalKeywords > 0) {
        indicators.push(`Found ${totalKeywords} suspicious keywords across ${details.filter(d => d.type === 'keyword').length} categories`);
    }

    // 2. Check for urgency indicators
    const exclamationCount = (emailContent.match(/!/g) || []).length;
    if (exclamationCount > 3) {
        riskScore += 15;
        indicators.push('Excessive urgency punctuation detected');
        details.push({
            type: 'urgency',
            title: 'Aggressive Urgency Tactics',
            description: `Detected ${exclamationCount} exclamation marks. Legitimate professional emails rarely use excessive punctuation to demand attention.`,
            severity: 'medium'
        });
    }

    // 3. URL Analysis — 3-Layer Detection
    // Try to get links that were extracted directly from DOM by content script
    let allLinks = urls;
    try {
        const savedEmailStr = await new Promise(res => chrome.storage.local.get(['currentEmail'], d => res(d.currentEmail)));
        if (savedEmailStr) {
            const savedEmail = JSON.parse(savedEmailStr);
            if (Array.isArray(savedEmail.extractedLinks) && savedEmail.extractedLinks.length > 0) {
                // Merge DOM-extracted links with regex-found links (deduplicate)
                const merged = [...new Set([...savedEmail.extractedLinks, ...urls])];
                allLinks = merged;
            }
        }
    } catch (e) { /* fallback to regex-found urls */ }

    if (allLinks.length > 0) {
        riskScore += Math.min(allLinks.length * 5, 20);
        warnings.push(`Found ${allLinks.length} link(s) — running 3-layer threat analysis...`);

        technical.push(`Total URLs found: ${allLinks.length}`);
        technical.push(`Secure (HTTPS) URLs: ${allLinks.filter(u => u.startsWith('https://')).length}`);

        allLinks.forEach((url, index) => {
            const layer1 = runLayer1(url);
            const layer2 = runLayer2(url, layer1.score);
            const finalScore = Math.round(layer1.score * 0.4 + layer2.confidence * 100 * 0.6);

            riskScore += Math.round(finalScore * 0.3);

            let severity = 'low';
            let emoji = '🟢';
            if (finalScore >= 70) { severity = 'high'; emoji = '🔴'; }
            else if (finalScore >= 40) { severity = 'medium'; emoji = '🟡'; }

            const truncated = url.length > 55 ? url.substring(0, 55) + '...' : url;
            const flagsText = layer1.flags.length > 0 ? `Flags: ${layer1.flags.slice(0, 3).join(' · ')}` : 'No rule violations found';

            details.push({
                type: 'url',
                title: `${emoji} Link ${index + 1} — Score: ${finalScore}/100`,
                description: `URL: ${truncated}\n${flagsText}\n${layer2.reason}`,
                severity: severity
            });

            if (severity === 'high') {
                warnings.push(`⚠️ High-risk link detected: ${url.substring(0, 60)}`);
            }
        });

        const highRiskLinks = allLinks.filter(url => {
            const l1 = runLayer1(url);
            return (l1.score * 0.4 + runLayer2(url, l1.score).confidence * 100 * 0.6) >= 70;
        });
        technical.push(`High-risk links: ${highRiskLinks.length}`);
        technical.push(`Layer 1 (Rules) + Layer 2 (Heuristic ML) applied to all ${allLinks.length} links`);
        if (allLinks.some(u => isShortUrl(u))) {
            technical.push(`⚠️ Short/redirect URLs detected — real destination hidden`);
        }
    }

    // 4. Check for generic greetings
    const genericGreetings = ['dear user', 'dear customer', 'valued member', 'account holder', 'valued customer'];
    if (genericGreetings.some(greeting => lowerContent.includes(greeting))) {
        riskScore += 10;
        indicators.push('Generic greeting pattern');
        details.push({
            type: 'greeting',
            title: 'Impersonal Greeting',
            description: 'Addressed as "User/Customer" instead of your name. Legitimate service providers typically use your name.',
            severity: 'low'
        });
    }

    // 5. Check for grammatical errors
    const grammarIssues = checkGrammarIssues(emailContent);
    if (grammarIssues.length > 0) {
        riskScore += grammarIssues.length * 5;
        indicators.push('Potential grammar/spelling issues');
        grammarIssues.forEach(issue => {
            details.push({
                type: 'grammar',
                title: 'Grammar Issue',
                description: `${issue}. Professional communications are usually reviewed for errors.`,
                severity: 'low'
            });
        });
    }

    // 6. Check email structure
    // Check for standard headers often missing in raw text copies or rudimentary fakes
    const missingHeaders = [];
    if (!emailContent.includes('Message-ID:') && !emailContent.includes('Message-Id:')) missingHeaders.push('Message-ID');
    if (!emailContent.includes('MIME-Version:')) missingHeaders.push('MIME-Version');
    if (!emailContent.includes('Received:')) missingHeaders.push('Received');

    // Logic: If we are analyzing raw source, these should exist. If analyzing body text, we can't blame them.
    // However, the original logic checked for '@' and '.', suggesting it was checking for basic validity.
    // We'll keep the basic check but clarify it.

    if (!emailContent.includes('@') || !emailContent.includes('.')) {
        riskScore += 10;
        warnings.push('Email content appears malformed');
        details.push({
            type: 'structure',
            title: 'Incomplete Email Structure',
            description: 'The analyzed content lacks standard email formatting (valid email addresses or domains). This may be a partial scan or a malformed message.',
            severity: 'medium'
        });
    }

    // 7. Check for personal information requests
    const piiKeywords = ['ssn', 'social security', 'credit card', 'bank account', 'password', 'pin', 'otp', 'cvv'];
    const foundPII = piiKeywords.filter(k => lowerContent.includes(k));
    if (foundPII.length > 0) {
        riskScore += 30;
        warnings.push(`Requests for sensitive data detected`);
        foundPII.forEach(pii => {
            details.push({
                type: 'pii',
                title: 'Sensitive Data Request',
                description: `Email explicitly mentions "${pii}". Legitimate organizations will NEVER ask for passwords/sensitive info via email.`,
                severity: 'high'
            });
        });
    }

    // 8. Header Analysis (SPF, DKIM, DMARC)
    const headerAnalysis = analyzeEmailHeaders(emailContent);

    // Add header info to technical details
    if (headerAnalysis.spf !== 'Unknown') technical.push(`SPF Status: ${headerAnalysis.spf}`);
    if (headerAnalysis.dkim !== 'Unknown') technical.push(`DKIM Status: ${headerAnalysis.dkim}`);
    if (headerAnalysis.dmarc !== 'Unknown') technical.push(`DMARC Status: ${headerAnalysis.dmarc}`);

    // Check for Return-Path mismatch (a common spoofing indicator)
    if (headerAnalysis.returnPath && sender) {
        const returnDomain = extractDomain(headerAnalysis.returnPath);
        if (senderDomain && returnDomain !== 'unknown' && senderDomain !== returnDomain) {
            // Allow some common mismatches (e.g. via bounces)
            if (!returnDomain.includes(senderDomain) && !senderDomain.includes(returnDomain)) {
                riskScore += 15;
                indicators.push(`Return-Path mismatch (${returnDomain} vs ${senderDomain})`);
                details.push({
                    type: 'spoofing',
                    title: 'Return-Path Mismatch',
                    description: `The email claims to be from ${senderDomain} but returns errors to ${returnDomain}. This often indicates spoofing.`,
                    severity: 'medium'
                });
            }
        }
    }

    // Check for failing auth
    if (headerAnalysis.spf === 'Fail' || headerAnalysis.dkim === 'Fail' || headerAnalysis.dmarc === 'Fail') {
        riskScore += 25;
        warnings.push('Email authentication failed (SPF/DKIM/DMARC)');
        details.push({
            type: 'auth_fail',
            title: 'Authentication Failure',
            description: 'The email failed technical authentication checks used to verify sender identity. Highly suspicious.',
            severity: 'high'
        });
    }

    // 9. Check sender information
    if (senderDomain && senderDomain !== 'unknown') {
        technical.push(`Sender Domain: ${senderDomain}`);

        // Check for domain mismatches
        if (urls.length > 0) {
            const externalDomains = urls.filter(url => {
                const urlDomain = extractUrlDomain(url);
                return urlDomain && urlDomain !== senderDomain && !urlDomain.includes('google') && !urlDomain.includes('microsoft');
            });

            if (externalDomains.length > 0) {
                riskScore += 15;
                indicators.push('Cross-domain linking detected');
                technical.push(`External domains referenced: ${externalDomains.length}`);

                // Add detail for this specific insight
                details.push({
                    type: 'mismatch',
                    title: 'Domain Mismatch',
                    description: `Links point to different domains (${externalDomains.length} found) than the sender's domain (${senderDomain}). This is a common phishing indicator.`,
                    severity: 'medium'
                });
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
    const isSpoofed = riskScore > 50 && (grammarIssues.length > 2 || totalKeywords > 3);

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
        recommendations: generateLocalRecommendations(riskScore, totalKeywords, urls.length, isPhishing),
        analysis_date: new Date().toISOString(),
        analyzed_by: 'Local AI Engine v2.0',
        confidence: Math.max(75, 100 - riskScore) + '%',
        senderDomain: senderDomain,
        subject: subject,
        from: sender,
        totalUrls: urls.length,
        suspiciousUrls: urls.filter(isSuspiciousUrl).length,
        features_checked: totalKeywords + urls.length + grammarIssues.length,
        urls: urls, // Add full URL list
        suspiciousUrls: suspiciousUrls // Add suspicious list
    };
}

// Analyze email headers (SPF, DKIM, DMARC)
function analyzeEmailHeaders(emailContent) {
    const headers = {
        spf: 'Unknown',
        dkim: 'Unknown',
        dmarc: 'Unknown',
        replyTo: null,
        returnPath: null
    };

    // Extract Reply-To
    const replyToMatch = emailContent.match(/^Reply-To:\s*(.+)$/im);
    if (replyToMatch) headers.replyTo = replyToMatch[1].trim();

    // Extract Return-Path
    const returnPathMatch = emailContent.match(/^Return-Path:\s*(.+)$/im);
    if (returnPathMatch) headers.returnPath = returnPathMatch[1].trim();

    // Check Authentication-Results (Best source)
    const authResults = emailContent.match(/Authentication-Results:[\s\S]*?(?=;|\n\S)/i);
    if (authResults) {
        const authText = authResults[0].toLowerCase();

        // SPF
        if (authText.includes('spf=pass')) headers.spf = 'Pass';
        else if (authText.includes('spf=fail')) headers.spf = 'Fail';
        else if (authText.includes('spf=softfail')) headers.spf = 'SoftFail';
        else if (authText.includes('spf=neutral')) headers.spf = 'Neutral';

        // DKIM
        if (authText.includes('dkim=pass')) headers.dkim = 'Pass';
        else if (authText.includes('dkim=fail')) headers.dkim = 'Fail';

        // DMARC
        if (authText.includes('dmarc=pass')) headers.dmarc = 'Pass';
        else if (authText.includes('dmarc=fail')) headers.dmarc = 'Fail';
    } else {
        // Fallback checks (Raw headers)
        if (emailContent.match(/Received-SPF: pass/i)) headers.spf = 'Pass';
        else if (emailContent.match(/Received-SPF: fail/i)) headers.spf = 'Fail';

        if (emailContent.match(/DKIM-Signature:/i)) {
            // Existence suggests it might be signed, but verification requires crypto. 
            // We can't verify signature validity locally without public keys, 
            // but we can acknowledge it's present.
            headers.dkim = 'Present (Unverified)';
        }
    }

    return headers;
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

// ═══════════════════════════════════════════════════════
// 3-LAYER PHISHING LINK DETECTION ENGINE
// ═══════════════════════════════════════════════════════

function extractUrls(text) {
    // Improved regex — catches more URL formats and strips trailing punctuation
    const urlRegex = /https?:\/\/[^\s"'<>)\]]+|www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s"'<>)\]]*/g;
    const raw = text.match(urlRegex) || [];
    return raw.map(u => u.replace(/[.,;:!?]+$/, ''));
}

function extractUrlDomain(url) {
    try {
        const full = url.startsWith('http') ? url : 'https://' + url;
        return new URL(full).hostname.replace(/^www\./, '');
    } catch { return null; }
}

function isShortUrl(url) {
    const shorteners = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'is.gd',
        'buff.ly', 'goo.gl', 't.co', 'fb.me', 'shorte.st', 'rb.gy',
        'cutt.ly', 'short.io', 'tiny.cc', 'bl.ink', 'smarturl.it'
    ];
    return shorteners.some(s => url.toLowerCase().includes(s));
}

function isSuspiciousUrl(url) {
    return runLayer1(url).score >= 40;
}

// ─── LAYER 1: Rule-Based Check ───────────────────────
function runLayer1(url) {
    const flags = [];
    let score = 0;
    const lower = url.toLowerCase();

    // TLD checks
    const badTlds = ['.xyz', '.top', '.club', '.online', '.download', '.gq', '.ml', '.tk', '.cf', '.ga', '.icu', '.pw'];
    if (badTlds.some(t => lower.includes(t))) { score += 30; flags.push('Suspicious TLD'); }

    // Shorteners
    if (isShortUrl(url)) { score += 40; flags.push('URL Shortener — hides destination'); }

    // URL length
    if (url.length > 100) { score += 15; flags.push(`Long URL (${url.length} chars)`); }

    // Digit ratio
    const digits = (url.match(/\d/g) || []).length;
    if (digits / url.length > 0.3) { score += 20; flags.push('High digit ratio'); }

    // Hyphens in domain
    try {
        const full = url.startsWith('http') ? url : 'https://' + url;
        const host = new URL(full).hostname;
        const hyphens = (host.match(/-/g) || []).length;
        if (hyphens >= 3) { score += 15; flags.push(`Excessive hyphens (${hyphens})`); }

        // Subdomain depth
        const parts = host.split('.');
        if (parts.length > 4) { score += 20; flags.push(`Deep subdomains (${parts.length - 2} levels)`); }

        // @ in URL (credential phishing trick)
        if (url.includes('@')) { score += 30; flags.push('@ symbol — possible credential trick'); }

        // Double slash after domain
        if (url.replace('https://', '').replace('http://', '').includes('//')) {
            score += 25; flags.push('Double slash after domain');
        }

        // Brand typosquatting
        const brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'netflix',
            'instagram', 'linkedin', 'twitter', 'youtube', 'whatsapp', 'telegram'];
        const found = brands.filter(b => host.includes(b) && !host.endsWith(b + '.com'));
        if (found.length > 0) { score += 35; flags.push(`Brand impersonation: ${found.join(', ')}`); }

        // Suspicious keywords in path
        const pathKeywords = ['login', 'verify', 'confirm', 'secure', 'update', 'account', 'bank', 'password', 'signin'];
        const pathLower = new URL(full).pathname.toLowerCase();
        const foundPath = pathKeywords.filter(k => pathLower.includes(k));
        if (foundPath.length > 0) { score += foundPath.length * 10; flags.push(`Suspicious path: ${foundPath.join(', ')}`); }
    } catch (e) { }

    // Unicode/punycode (homograph attack)
    if (/xn--/.test(url)) { score += 40; flags.push('Punycode/homograph attack'); }

    // IP address instead of domain
    if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url)) { score += 35; flags.push('IP address used instead of domain'); }

    return { score: Math.min(score, 100), flags };
}

// ─── LAYER 2: Heuristic ML-Simulation ───────────────
function runLayer2(url, layer1Score) {
    let confidence = layer1Score / 100; // base from layer 1
    const reasons = [];

    // Feature: entropy of domain (random-looking = suspicious)
    const domain = extractUrlDomain(url) || url;
    const entropy = calcEntropy(domain);
    if (entropy > 3.8) { confidence = Math.min(confidence + 0.15, 1); reasons.push('High domain entropy (random-looking)'); }

    // Feature: vowel/consonant ratio
    const vowels = (domain.match(/[aeiou]/gi) || []).length;
    const consonants = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    if (consonants > 0 && vowels / consonants < 0.25) {
        confidence = Math.min(confidence + 0.1, 1);
        reasons.push('Abnormal vowel-consonant ratio (computer-generated domain)');
    }

    // Feature: digit count in domain name
    const digitCount = (domain.match(/\d/g) || []).length;
    if (digitCount > 3) { confidence = Math.min(confidence + 0.1, 1); reasons.push('Many digits in domain'); }

    // Feature: extra-long path/query
    try {
        const full = url.startsWith('http') ? url : 'https://' + url;
        const parsed = new URL(full);
        if (parsed.pathname.length > 50) { confidence = Math.min(confidence + 0.08, 1); reasons.push('Unusually long path'); }
        if (parsed.search.length > 80) { confidence = Math.min(confidence + 0.08, 1); reasons.push('Long query string (possible tracking/obfuscation)'); }
    } catch (e) { }

    const reason = reasons.length > 0
        ? `ML signals: ${reasons.slice(0, 2).join(' · ')}`
        : 'No ML anomalies detected';

    return { confidence: parseFloat(confidence.toFixed(2)), reason };
}

// Shannon entropy helper
function calcEntropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    return Object.values(freq).reduce((acc, v) => {
        const p = v / str.length;
        return acc - p * Math.log2(p);
    }, 0);
}

// ─── LAYER 3: External API Check (async) ─────────────
async function runLayer3(url) {
    const results = { score: 0, warnings: [], sources: [] };

    // Try Google Safe Browsing (no key needed for basic lookup)
    try {
        // PhishTank free public API
        const encoded = encodeURIComponent(url);
        const ptRes = await fetch(`https://checkurl.phishtank.com/checkurl/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'MailXpose/1.0' },
            body: `url=${encoded}&format=json&app_key=`,
            signal: AbortSignal.timeout(4000)
        });
        if (ptRes.ok) {
            const ptData = await ptRes.json();
            if (ptData.results && ptData.results.in_database) {
                if (ptData.results.valid) {
                    results.score += 50;
                    results.warnings.push('⚠️ Listed in PhishTank phishing database');
                    results.sources.push('PhishTank: PHISHING');
                } else {
                    results.sources.push('PhishTank: Verified safe');
                }
            }
        }
    } catch (e) { results.sources.push('PhishTank: Unavailable'); }

    return results;
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
            updateSubscriptionUI(); // Refresh usage bar
        });
    });
}

// Daily Reset Check
async function checkDailyReset() {
    const data = await storage.get(['lastResetDate', 'scanCount']);
    const now = new Date();
    const today = now.toISOString().split('T')[0];

    if (data.lastResetDate !== today) {
        console.log('🌅 New day detected! Resetting daily scan count...');
        await storage.set({
            lastResetDate: today,
            scanCount: 0
        });
        updateStats({ scanCount: 0 });
        updateSubscriptionUI();
    }
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

    const riskColor = results.risk_level === 'HIGH' ? '#f43f5e' :
        results.risk_level === 'MEDIUM' ? '#fbbf24' : '#10b981';

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
                    <div style="font-size: 0.9rem; color: var(--text-dim); margin-top: 5px;">
                        Report ID: ${results.report_id || 'N/A'} • ${new Date(results.analysis_date).toLocaleString()}
                    </div>
                </div>
            </div>
            
            <!-- Risk Score -->
            <div class="risk-meter" style="margin: 20px 0; text-align: center;">
                <div class="risk-score risk-score-animation" style="font-size: 3.5rem; font-weight: 800; color: ${riskColor}; margin: 10px 0;">
                    ${results.risk_score || 0}<span style="font-size: 1.5rem; color: var(--text-dim);">/100</span>
                </div>
                <div class="risk-level" style="color: ${riskColor}; font-size: 1.3rem; font-weight: bold; margin: 10px 0;">
                    ${results.risk_level || 'MEDIUM'} RISK LEVEL
                </div>
                <div style="font-size: 0.9rem; color: var(--text-dim); margin-top: 10px;">
                    Confidence: ${results.confidence || '85%'} • Analyzed by: ${results.analyzed_by || 'Local Engine'}
                </div>
            </div>
            
            <!-- Quick Stats -->
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0;">
                <div style="padding: 15px; background: rgba(255, 158, 0, 0.1); border-radius: 10px; text-align: center; border-left: 4px solid ${indicatorCount > 0 ? '#ff9e00' : '#4361ee'};">
                    <div style="font-size: 1.8rem; font-weight: bold; color: ${indicatorCount > 0 ? '#ff9e00' : '#4361ee'};">
                        ${indicatorCount}
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 5px;">Indicators</div>
                </div>
                <div style="padding: 15px; background: rgba(239, 71, 111, 0.1); border-radius: 10px; text-align: center; border-left: 4px solid ${warningCount > 0 ? '#ef476f' : '#4361ee'};">
                    <div style="font-size: 1.8rem; font-weight: bold; color: ${warningCount > 0 ? '#ef476f' : '#4361ee'};">
                        ${warningCount}
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 5px;">Warnings</div>
                </div>
                <div style="padding: 15px; background: rgba(67, 97, 238, 0.1); border-radius: 10px; text-align: center; border-left: 4px solid #4361ee;">
                    <div style="font-size: 1.8rem; font-weight: bold; color: #4361ee;">
                        ${detailCount}
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 5px;">Details</div>
                </div>
                <div style="padding: 15px; background: rgba(114, 9, 183, 0.1); border-radius: 10px; text-align: center; border-left: 4px solid #7209b7;">
                    <div style="font-size: 1.8rem; font-weight: bold; color: #7209b7;">
                        ${techCount}
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 5px;">Technical</div>
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
                                <div style="font-weight: 600; color: #333; word-break: break-word;">${results.subject}</div>
                            </div>
                        ` : ''}
                        ${results.from ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Sender</div>
                                <div style="font-weight: 600; color: #333; word-break: break-word;">${results.from}</div>
                            </div>
                        ` : ''}
                        ${results.senderDomain ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Domain</div>
                                <div style="font-weight: 600; color: #333;">${results.senderDomain}</div>
                            </div>
                        ` : ''}
                        ${results.totalUrls !== undefined ? `
                            <div>
                                <div style="font-size: 0.8rem; color: #6c757d;">Links</div>
                                <div style="font-weight: 600; color: ${results.totalUrls > 0 ? '#ef476f' : '#06d6a0'};">${results.totalUrls} (${results.suspiciousUrls ? results.suspiciousUrls.length : 0} suspicious)</div>
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
                    <div class="card-icon" style="background: rgba(251, 191, 36, 0.1); color: #fbbf24; box-shadow: 0 4px 10px rgba(251, 191, 36, 0.1);">
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
                                    ${ind}
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
                    <div class="card-icon" style="background: rgba(244, 63, 94, 0.1); color: #f43f5e; box-shadow: 0 4px 10px rgba(244, 63, 94, 0.1);">
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
                                    ⚠️ ${warn}
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
                    <div class="card-icon" style="background: rgba(99, 102, 241, 0.1); color: #6366f1; box-shadow: 0 4px 10px rgba(99, 102, 241, 0.1);">
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
                                    ${detail.title || 'Finding'}
                                </div>
                                <div style="font-size: 0.7rem; padding: 2px 8px; background: ${severityColor}; color: white; border-radius: 10px; font-weight: 600;">
                                    ${(detail.severity || 'info').toUpperCase()}
                                </div>
                            </div>
                            <div style="color: #666; font-size: 0.9rem; margin-left: 34px;">
                                ${detail.description || JSON.stringify(detail)}
                            </div>
                            ${detail.type ? `
                                <div style="font-size: 0.7rem; color: #999; margin-top: 8px; margin-left: 34px;">
                                    <i class="fas fa-tag" style="margin-right: 5px;"></i>
                                    ${detail.type}
                                </div>
                            ` : ''}
                        </div>
                    `}).join('')}
                </div>
            </div>
        ` : ''}

        <!-- Suspicious/All Links Section -->
        ${(results.suspiciousUrls && results.suspiciousUrls.length > 0) || (results.is_phishing && results.urls && results.urls.length > 0) ? `
            <div class="card" style="margin-bottom: 20px; animation: fadeIn 0.85s ease;">
                <div class="card-header">
                    <div class="card-icon" style="background: rgba(239, 68, 68, 0.1); color: #ef4444; box-shadow: 0 4px 10px rgba(239, 68, 68, 0.1);">
                        <i class="fas fa-link"></i>
                    </div>
                    <h2 class="card-title">
                        ${results.suspiciousUrls && results.suspiciousUrls.length > 0 ?
                `Detected Phishing Links (${results.suspiciousUrls.length})` :
                `Links in Suspicious Email (${results.urls.length})`}
                    </h2>
                </div>
                <div class="result-content" style="padding: 0 20px 20px;">
                    <p style="color: #6c757d; margin-bottom: 15px; font-size: 0.9rem;">
                        ${results.suspiciousUrls && results.suspiciousUrls.length > 0 ?
                'The following links were identified as potentially malicious. <strong>DO NOT CLICK</strong> these links.' :
                'This email is flagged as phishing. All links should be considered dangerous. <strong>DO NOT CLICK</strong>.'}
                    </p>
                    ${(results.suspiciousUrls && results.suspiciousUrls.length > 0 ? results.suspiciousUrls : results.urls).map((url, index) => `
                        <div style="padding: 12px; margin: 8px 0; background: #fff5f5; border-radius: 8px; border: 1px solid #fed7d7; display: flex; align-items: center; gap: 10px;">
                            <div style="width: 20px; height: 20px; background: #ef4444; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; flex-shrink: 0;">
                                ${index + 1}
                            </div>
                            <div style="font-family: monospace; word-break: break-all; color: #c53030; font-size: 0.85rem; flex: 1;">
                                ${url}
                            </div>
                            <div style="font-size: 0.8rem; color: #e53e3e; font-weight: bold;">
                                <i class="fas fa-ban"></i>
                            </div>
                        </div>
                    `).join('')}
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
                                <div style="font-weight: 600; color: #333;">${tech}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        ` : ''}


        
        <!--Recommendations -->
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
        
        <!--Action Buttons-- >
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
            </div>
        </div>
    </div>

    <!-- PDF Expose Button (Standalone) -->
    <div style="margin-top: 20px; margin-bottom: 20px; animation: fadeIn 1.2s ease;">
        <button id="exportPdfBtn" style="width: 100%; padding: 16px; background: linear-gradient(135deg, #ef476f, #f78c6b); color: white; border: none; border-radius: 12px; font-size: 1.1rem; font-weight: bold; cursor: pointer; box-shadow: 0 8px 20px rgba(239, 71, 111, 0.3); display: flex; align-items: center; justify-content: center; gap: 10px; transition: transform 0.2s;">
            <i class="fas fa-file-pdf" style="font-size: 1.3rem;"></i> 
            PDF Expose
        </button>
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
        const response = await fetch(`${API_BASE_URL} /extension/reports / sync`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${extensionToken} `
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
                analysisTime: results.analysisTime || 0,
                apiKey: (userInfo || {}).apiKey // Send apiKey in body to avoid CORS
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
                <div style="font-weight: 600; color: #333;">${report.subject || 'Unknown Subject'}</div>
                <div style="font-size: 0.8rem; color: #6c757d;">${new Date(report.savedAt || report.analysis_date).toLocaleString()}</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 1.5rem; font-weight: 700; color: ${report.risk_level === 'HIGH' ? '#ef476f' : report.risk_level === 'MEDIUM' ? '#ff9e00' : '#06d6a0'}">
                    ${report.risk_score}
                </div>
                <div style="font-size: 0.7rem; color: #6c757d;">${report.risk_level} risk</div>
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
    const existingPopup = document.querySelector('.feature-popup-overlay');
    if (existingPopup) existingPopup.remove();

    const popup = document.createElement('div');
    popup.className = 'feature-popup-overlay';
    popup.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 10000; backdrop-filter: blur(5px);';

    popup.innerHTML = `
    <div style="background: #1a1a2e; padding: 35px; border-radius: 24px; max-width: 320px; text-align: center; border: 1px solid rgba(15, 240, 252, 0.2); box-shadow: 0 20px 60px rgba(0,0,0,0.5);">
            <div style="width: 70px; height: 70px; background: rgba(15, 240, 252, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; color: #0ff0fc; font-size: 32px; border: 2px solid rgba(15, 240, 252, 0.3);">
                ${icon}
            </div>
            <div id="popupContent" style="color: white; line-height: 1.5; font-size: 0.95rem;">${message}</div>
    </div>
    `;

    document.body.appendChild(popup);

    // If message is just text, it might need a close button
    if (!message.includes('<button')) {
        const content = document.getElementById('popupContent');
        const closeBtn = document.createElement('button');
        closeBtn.textContent = 'Got it!';
        closeBtn.style.cssText = 'background: linear-gradient(135deg, #0ff0fc, #ff00ff); color: white; border: none; padding: 12px 30px; border-radius: 25px; font-weight: 600; cursor: pointer; margin-top: 20px; width: 100%;';
        closeBtn.onclick = () => popup.remove();
        content.appendChild(closeBtn);
    }
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
            '  No indicators detected'
        }

⚠️ SECURITY WARNINGS
${results.warnings && results.warnings.length > 0 ?
            results.warnings.map((warn, i) => `  ${i + 1}. ⚠️ ${warn}`).join('\n') :
            '  No warnings'
        }

✅ RECOMMENDED ACTIONS
${results.recommendations && results.recommendations.length > 0 ?
            results.recommendations.slice(0, 5).map((rec, i) => `  ${i + 1}. ${rec.replace(/\*\*/g, '')}`).join('\n') :
            '  No specific recommendations'
        }

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

    const exportFileDefaultName = `email - analysis - ${results.report_id || Date.now()}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    document.body.appendChild(linkElement);
    linkElement.click();
    document.body.removeChild(linkElement);

    showNotification('✅ Report exported as JSON', 'success');
}

// Export report as PDF
function exportReportAsPDF(results = currentAnalysis) {
    if (!results) {
        showNotification('No analysis to export', 'error');
        return;
    }

    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        // --- Header ---
        doc.setFillColor(67, 97, 238); // Primary blue
        doc.rect(0, 0, 210, 40, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(22);
        doc.setFont('helvetica', 'bold');
        doc.text('Email Forensic Analysis Report', 105, 20, { align: 'center' });

        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.text(`Generated: ${new Date().toLocaleString()}`, 105, 30, { align: 'center' });

        let yPos = 50;

        // --- Risk Score Section ---
        doc.setTextColor(51, 51, 51);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('Risk Assessment', 20, yPos);
        yPos += 10;

        const scoreColor = results.risk_level === 'HIGH' ? [239, 71, 111] :
            results.risk_level === 'MEDIUM' ? [255, 158, 0] : [6, 214, 160];

        doc.setTextColor(...scoreColor);
        doc.setFontSize(40);
        doc.setFont('helvetica', 'bold');
        doc.text(`${results.risk_score}/100`, 20, yPos + 10);

        doc.setFontSize(16);
        doc.text(`${results.risk_level} RISK`, 90, yPos + 5);

        doc.setFontSize(12);
        doc.setTextColor(100, 100, 100);
        doc.text(`Suspicious: ${results.is_suspicious ? 'YES' : 'NO'}`, 90, yPos + 12);
        doc.text(`Phishing: ${results.is_phishing ? 'YES' : 'NO'}`, 140, yPos + 12);

        yPos += 30;

        // --- Email Details ---
        doc.setDrawColor(200, 200, 200);
        doc.line(20, yPos, 190, yPos);
        yPos += 10;

        doc.setTextColor(51, 51, 51);
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.text('Email Details', 20, yPos);
        yPos += 8;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.text(`Subject: ${results.subject || 'N/A'}`, 20, yPos);
        yPos += 6;
        doc.text(`Sender: ${results.from || 'N/A'}`, 20, yPos);
        yPos += 6;
        doc.text(`Date: ${results.date || 'unknown'}`, 20, yPos);

        yPos += 15;

        // --- Technical Analysis ---
        if (results.technical && results.technical.length > 0) {
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(12);
            doc.text('Technical Analysis', 20, yPos);
            yPos += 8;

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(10);

            results.technical.forEach(tech => {
                const splitTech = doc.splitTextToSize(`• ${tech}`, 170);
                doc.text(splitTech, 20, yPos);
                yPos += (splitTech.length * 6);

                // Page break check
                if (yPos > 270) {
                    doc.addPage();
                    yPos = 20;
                }
            });
            yPos += 10;
        }

        // --- Recommendations ---
        if (results.recommendations && results.recommendations.length > 0) {
            // Page break check
            if (yPos > 250) {
                doc.addPage();
                yPos = 20;
            }

            doc.setFont('helvetica', 'bold');
            doc.setFontSize(12);
            doc.text('Recommendations', 20, yPos);
            yPos += 8;

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(10);

            results.recommendations.forEach((rec, i) => {
                const cleanRec = rec.replace(/\*\*/g, '');
                const splitRec = doc.splitTextToSize(`${i + 1}. ${cleanRec}`, 170);
                doc.text(splitRec, 20, yPos);
                yPos += (splitRec.length * 6);
            });
        }

        // Save PDF
        doc.save(`Analysis_Report_${results.report_id || Date.now()}.pdf`);
        showNotification('✅ PDF Report downloaded', 'success');

    } catch (e) {
        console.error('PDF generation error:', e);
        showNotification('Failed to generate PDF: ' + e.message, 'error');
    }
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
