// Background service worker for Email Forensic Analyzer - FIXED
console.log('✅ Background script started');

// Extension install/update
chrome.runtime.onInstalled.addListener(() => {
    console.log('✅ Email Forensic Analyzer Extension Installed');

    // Set default settings
    chrome.storage.local.set({
        autoScan: false,
        notifications: true,
        apiEndpoint: 'https://mailxpose.tech/api/api',
        scanCount: 0,
        threatCount: 0,
        installed: true,
        version: '2.2'
    });

    // Create context menu
    createContextMenu();
});

// Create context menu function - FIXED
function createContextMenu() {
    chrome.contextMenus.removeAll(() => {
        if (chrome.runtime.lastError) {
            console.log('Error removing menus:', chrome.runtime.lastError);
        }

        chrome.contextMenus.create({
            id: 'analyzeEmail',
            title: '🔍 Analyze Email',
            contexts: ['page'],
            documentUrlPatterns: ['https://mail.google.com/*']
        }, () => {
            if (chrome.runtime.lastError) {
                console.log('Context menu creation error:', chrome.runtime.lastError);
            } else {
                console.log('✅ Context menu created successfully');
            }
        });
    });
}

// Listen for context menu clicks - MOVED OUTSIDE createContextMenu
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'analyzeEmail') {
        console.log('Context menu clicked, analyzing email...');

        // Try to send message to content script
        if (tab && tab.id) {
            chrome.tabs.sendMessage(tab.id, {
                action: 'testButton'
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.log('Could not send message to tab:', chrome.runtime.lastError.message);
                    // Open popup directly
                    openPopupWindow();
                }
            });
        } else {
            openPopupWindow();
        }
    }
});

// Listen for messages from content.js and popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Background received:', request.action);

    switch (request.action) {
        case 'openPopupForAnalysis':
            console.log('📧 Opening popup for analysis...');

            const emailData = request.data || {};

            // Priority 1: Use data from message
            if (emailData.emailContent) {
                chrome.storage.local.set({
                    currentEmail: emailData.emailContent,
                    timestamp: Date.now(),
                    lastEmailId: emailData.emailId
                }, () => {
                    console.log('✅ Email stored from message, opening popup...');
                    openPopupWindow();
                });
            } else {
                // Priority 2: Try to get existing email from storage
                chrome.storage.local.get(['currentEmail'], (result) => {
                    if (result.currentEmail) {
                        console.log('✅ Found stored email, opening popup...');
                        openPopupWindow();
                    } else {
                        console.log('⚠️ No email data found in message or storage, opening popup anyway...');
                        openPopupWindow();
                    }
                });
            }

            sendResponse({ success: true, message: 'Popup opening initiated' });
            break;

        case 'openPopup':
            console.log('Open popup requested from button');
            openPopupWindow();
            sendResponse({ success: true });
            break;

        case 'showPopup':
            console.log('Show popup requested');
            openPopupWindow();
            sendResponse({ success: true });
            break;

        case 'getSettings':
            chrome.storage.local.get(['autoScan', 'notifications', 'apiEndpoint'], (settings) => {
                sendResponse(settings);
            });
            return true;

        case 'updateScanCount':
            chrome.storage.local.get(['scanCount', 'threatCount'], (data) => {
                const newCount = (data.scanCount || 0) + 1;
                const isThreat = request.data?.isThreat || false;
                let newThreatCount = data.threatCount || 0;

                if (isThreat) {
                    newThreatCount += 1;
                }

                chrome.storage.local.set({
                    scanCount: newCount,
                    threatCount: newThreatCount
                }, () => {
                    sendResponse({ newCount, newThreatCount });
                });
            });
            return true;

        case 'showNotification':
            showNotification(request.title, request.message);
            sendResponse({ success: true });
            break;

        case 'testConnection':
            sendResponse({
                connected: true,
                message: 'Background script is running',
                version: '2.2'
            });
            break;

        case 'getCurrentEmail':
            chrome.storage.local.get(['currentEmail'], (result) => {
                sendResponse({ emailContent: result.currentEmail });
            });
            return true;

        case 'logout':
            console.log('Logging out extension...');
            const keysToRemove = [
                'extensionToken',
                'isLinked',
                'userInfo',
                'apiKey',
                'currentEmail',
                'lastEmailId',
                'lastFetched',
                'lastAnalysis',
                'savedReports',
                'linkedEmail',
                'timestamp'
            ];
            chrome.storage.local.remove(keysToRemove, () => {
                console.log('✅ All extension data cleared');
                sendResponse({ success: true });
            });
            return true;

        default:
            console.log('Unknown action:', request.action);
            sendResponse({ error: 'Unknown action' });
    }

    return true;
});

// Open popup in SAME WINDOW as POPUP (not tab)
function openPopupWindow() {
    const popupUrl = chrome.runtime.getURL('popup.html');

    // Method 1: Try to open extension popup (if user clicked extension icon)
    try {
        chrome.action.openPopup && chrome.action.openPopup();
        console.log('✅ Extension popup opened');
        return;
    } catch (e) {
        console.log('Cannot open extension popup:', e);
    }

    // Method 2: Create popup window in SAME window context
    chrome.windows.getCurrent((currentWindow) => {
        // Create popup attached to current window
        chrome.windows.create({
            url: popupUrl,
            type: 'popup',
            width: 850,
            height: 700,
            left: currentWindow.left + 50, // Slightly right
            top: currentWindow.top + 50,   // Slightly down
            focused: true
        }, (newWindow) => {
            if (chrome.runtime.lastError) {
                console.error('Popup window error:', chrome.runtime.lastError);

                // Fallback: Open in new tab in SAME window
                chrome.tabs.create({
                    url: popupUrl,
                    active: true,
                    windowId: currentWindow.id // Same window
                });
            } else {
                console.log('✅ Popup window created in same window');
            }
        });
    });
}

// Handle notifications
function showNotification(title, message) {
    chrome.storage.local.get(['notifications'], (result) => {
        if (result.notifications !== false) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icon128.png'),
                title: title || 'Email Forensic Analyzer',
                message: message || 'Analysis complete',
                priority: 2
            }, (notificationId) => {
                if (chrome.runtime.lastError) {
                    console.warn('Notification error:', chrome.runtime.lastError);
                }
            });
        }
    });
}

// Keep service worker alive
chrome.runtime.onStartup.addListener(() => {
    console.log('Extension starting up');
    chrome.storage.local.set({
        lastStartup: new Date().toISOString(),
        dailyScanCount: 0
    });
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.includes('mail.google.com')) {
        console.log('Gmail page loaded, content script should be active');
    }
});

// Periodic cleanup (optional)
setInterval(() => {
    chrome.storage.local.get(['savedReports'], (data) => {
        const reports = data.savedReports || [];
        if (reports.length > 100) {
            const cleaned = reports.slice(0, 50);
            chrome.storage.local.set({ savedReports: cleaned });
        }
    });
}, 3600000); // Every hour