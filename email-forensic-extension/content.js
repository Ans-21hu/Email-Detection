// Email Forensic Analyzer - IMPROVED VERSION
const _SCRIPT_INST_ID = Date.now() + Math.random();
window._EMAIL_ANALYZER_ID = _SCRIPT_INST_ID;
console.log('✅ Email Forensic Analyzer Extension Loaded [' + _SCRIPT_INST_ID + ']');

// Configuration
const CONFIG = {
    checkInterval: 1000, // Check every 1 second
    maxRetries: 10,
    buttonClassName: 'email-analyzer-btn',
    containerClassName: 'email-analyzer-container'
};

// Track current email
let currentEmailId = null;
let buttonInjected = false;
let retryCount = 0;

// Helper to check if extension context is still valid
function isContextValid() {
    try {
        return !!(chrome && chrome.runtime && chrome.runtime.id);
    } catch (e) {
        return false;
    }
}

// Main function to check and inject button
function checkAndInjectButton() {
    if (window._EMAIL_ANALYZER_ID !== _SCRIPT_INST_ID || !isContextValid()) {
        // Stop checking and cleanup if we are an orphaned or invalidated instance
        removeButton();
        return;
    }
    if (retryCount >= CONFIG.maxRetries) {
        console.log('Max retries reached, stopping checks');
        return;
    }

    retryCount++;

    // Check if we're on Gmail
    if (!window.location.href.includes('mail.google.com')) {
        return;
    }

    // Check if we're viewing a specific email
    const emailId = getCurrentEmailId();

    if (emailId && emailId !== currentEmailId) {
        console.log(`📧 New email opened: ${emailId}`);
        currentEmailId = emailId;
        buttonInjected = false;

        // Wait a bit for email to fully load
        setTimeout(() => {
            injectButton();
        }, 800);
    }

    // If no email is open but we previously had one, reset
    if (!emailId && currentEmailId) {
        console.log('Email closed, resetting state');
        currentEmailId = null;
        buttonInjected = false;
        removeButton();
    }
}

// Get current email ID from URL or DOM
function getCurrentEmailId() {
    try {
        // Method 1: Check URL for email ID
        const url = window.location.href;
        const urlMatch = url.match(/[#&](\w{16,})/);
        if (urlMatch && urlMatch[1]) {
            return urlMatch[1];
        }

        // Method 2: Check for email thread in DOM
        const threadElement = document.querySelector('[data-thread-id], [data-message-id], [data-legacy-thread-id]');
        if (threadElement) {
            const threadId = threadElement.getAttribute('data-thread-id') ||
                threadElement.getAttribute('data-message-id') ||
                threadElement.getAttribute('data-legacy-thread-id');
            if (threadId) return threadId;
        }

        // Method 3: Check for email header
        const emailHeader = document.querySelector('.h7, .ha, [role="heading"]');
        if (emailHeader && emailHeader.textContent.trim()) {
            return 'email-' + hashString(emailHeader.textContent);
        }

        // Method 4: Check for reply buttons (only present when email is open)
        const hasReplyButtons = document.querySelector('[aria-label*="Reply" i], [data-tooltip*="Reply" i], [title*="Reply" i]');
        if (hasReplyButtons) {
            return 'active-email';
        }

        return null;
    } catch (error) {
        console.error('Error getting email ID:', error);
        return null;
    }
}

// Simple string hash
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
}

// Inject button into Gmail UI
function injectButton() {
    if (buttonInjected) {
        return;
    }

    console.log('🔧 Attempting to inject button...');

    // Remove any existing button first
    removeButton();

    // Find the best location for the button
    const buttonLocation = findButtonLocation();

    if (!buttonLocation) {
        console.log('❌ Could not find suitable location for button');
        return;
    }

    // Create button container
    const buttonContainer = document.createElement('div');
    buttonContainer.className = CONFIG.containerClassName;
    buttonContainer.style.cssText = `
        display: inline-block;
        margin-left: 12px;
        margin-right: 8px;
        vertical-align: middle;
    `;

    // Create the analyze button
    const button = document.createElement('button');
    button.id = 'email-analyzer-btn';
    button.className = CONFIG.buttonClassName;
    button.innerHTML = `
        <span style="display: flex; align-items: center; gap: 8px; font-size: 14px;">
            <span style="font-size: 16px;">🔍</span>
            <span>Analyze Email</span>
        </span>
    `;

    // Button styling
    button.style.cssText = `
        background: linear-gradient(135deg, #4361ee 0%, #3046bc 100%);
        color: white;
        border: none;
        border-radius: 20px;
        padding: 10px 20px;
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        display: flex;
        align-items: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 12px rgba(67, 97, 238, 0.3);
        white-space: nowrap;
        font-family: 'Google Sans', Roboto, Arial, sans-serif;
    `;

    // Hover effects
    button.addEventListener('mouseenter', () => {
        button.style.transform = 'translateY(-2px)';
        button.style.boxShadow = '0 4px 12px rgba(37, 99, 235, 0.4)';
        button.style.background = 'linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%)';
    });

    button.addEventListener('mouseleave', () => {
        button.style.transform = 'translateY(0)';
        button.style.boxShadow = '0 2px 8px rgba(37, 99, 235, 0.3)';
        button.style.background = 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)';
    });

    // Click handler
    button.addEventListener('click', handleAnalyzeClick);

    // Add to container
    buttonContainer.appendChild(button);

    // Insert into target location
    try {
        buttonLocation.appendChild(buttonContainer);
        buttonInjected = true;
        console.log('✅ Button injected successfully!');

        // Add a subtle animation
        button.style.animation = 'fadeIn 0.3s ease';

    } catch (error) {
        console.error('Error injecting button:', error);
    }
}

// Find the best location for the button
function findButtonLocation() {
    const locations = [
        // Primary toolbar locations
        document.querySelector('.G-Ni.J-J5-Ji.ajX'), // Top right actions
        document.querySelector('[gh="mtb"]'), // Message toolbar
        document.querySelector('.G-tF.J-J5-Ji'), // More actions
        document.querySelector('.iH.bzn'), // Reply area
        document.querySelector('.aeJ'), // Three dots menu area

        // Email header area
        document.querySelector('.ha') || document.querySelector('.h7'), // Email header
        document.querySelector('[role="banner"]'), // Banner area

        // Thread actions
        document.querySelector('.brC-aT5-aOt-Jw'), // Thread actions
        document.querySelector('.aCQ'), // Compose area

        // Mobile/adaptive UI
        document.querySelector('.aDh'), // Floating action bar
        document.querySelector('.aeN'), // Navigation

        // Subject line area
        document.querySelector('h2')?.closest('div'),
        document.querySelector('[data-thread-perm-id]')?.parentElement,

        // Last resort: near sender info
        document.querySelector('.gD')?.closest('.ha'),

        // Ultimate fallback: create our own toolbar
        createToolbarContainer()
    ];

    for (const location of locations) {
        if (location && document.body.contains(location)) {
            console.log('Found location:', location.className || location.tagName);
            return location;
        }
    }

    return null;
}

// Create a custom toolbar container if none exists
function createToolbarContainer() {
    const emailHeader = document.querySelector('.ha, .h7, [role="heading"]');
    if (!emailHeader) return null;

    // Create a container div
    const container = document.createElement('div');
    container.className = 'custom-analyzer-toolbar';
    container.style.cssText = `
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px;
        background: #f8f9fa;
        border-bottom: 1px solid #e0e0e0;
    `;

    // Insert after email header
    emailHeader.parentNode.insertBefore(container, emailHeader.nextSibling);
    return container;
}

// Remove button
function removeButton() {
    const existingButton = document.querySelector(`.${CONFIG.containerClassName}, #email-analyzer-btn`);
    if (existingButton) {
        existingButton.remove();
        buttonInjected = false;
    }
}

// Handle analyze button click
async function handleAnalyzeClick() {
    if (window._EMAIL_ANALYZER_ID !== _SCRIPT_INST_ID) {
        console.warn('Orphaned script instance - ignoring click');
        return;
    }
    console.log('Analyze button clicked');

    const button = document.getElementById('email-analyzer-btn');
    if (!button) return;

    // Update button state
    const originalHTML = button.innerHTML;
    const originalCursor = button.style.cursor;

    button.innerHTML = `
        <span style="display: flex; align-items: center; gap: 8px; font-size: 14px;">
            <span style="font-size: 16px;">⏳</span>
            <span>Analyzing...</span>
        </span>
    `;
    button.disabled = true;
    button.style.opacity = '0.8';
    button.style.cursor = 'wait';

    try {
        // Get email content
        const emailContent = getEmailContent();

        if (!emailContent) {
            throw new Error('Could not extract email content');
        }

        console.log('📧 Email extracted, length:', emailContent.length);

        // Safe check for extension context
        if (!isContextValid()) {
            showTemporaryMessage('❌ Extension reloaded. Please refresh Gmail to continue.', 'error');
            removeButton();
            return;
        }

        // Send message to background to open popup
        chrome.runtime.sendMessage({
            action: 'openPopupForAnalysis',
            data: {
                success: true,
                emailId: currentEmailId,
                emailContent: emailContent
            }
        }, (response) => {
            // Check for lastError immediately
            if (chrome.runtime.lastError) {
                console.warn('Runtime error:', chrome.runtime.lastError);
                showTemporaryMessage('✅ Email captured! Click extension icon.', 'success');
            } else {
                console.log('Background response:', response);
                showTemporaryMessage('✅ Analysis started! Popup opening...', 'success');
            }
        });

    } catch (error) {
        if (error.message && error.message.includes('context invalidated')) {
            console.warn('Silent failure: Extension context invalidated');
            showTemporaryMessage('❌ Extension reloaded. Please refresh Gmail.', 'error');
        } else {
            console.error('Error in analyze:', error);
            showTemporaryMessage('❌ Error: ' + error.message, 'error');
        }
    }
    finally {
        // Reset button after 2 seconds
        setTimeout(() => {
            if (button && button.parentNode) {
                button.innerHTML = originalHTML;
                button.disabled = false;
                button.style.opacity = '1';
                button.style.cursor = originalCursor;
            }
        }, 2000);
    }
}

// Get email content
function getEmailContent() {
    try {
        // Try multiple selectors for different Gmail versions
        const emailSelectors = [
            '.a3s.aiL',
            '.ii.gt',
            '.adn.ads',
            '.gs',
            '.hx',
            '[role="listitem"]',
            '[data-message-body]',
            '.gmail_default'
        ];

        let emailBody = null;
        for (const selector of emailSelectors) {
            const element = document.querySelector(selector);
            if (element && element.textContent && element.textContent.trim().length > 50) {
                emailBody = element;
                console.log('Found email with selector:', selector);
                break;
            }
        }

        if (!emailBody) {
            // Try to find the main email container
            const emailContainers = document.querySelectorAll('div');
            for (const container of emailContainers) {
                if (container.textContent && container.textContent.length > 200 &&
                    container.textContent.includes('@') &&
                    !container.querySelector('iframe')) {
                    emailBody = container;
                    break;
                }
            }
        }

        if (!emailBody) {
            throw new Error('No email content found');
        }

        // Get metadata
        const subject = document.querySelector('h2[data-thread-perm-id]')?.textContent?.trim() ||
            document.querySelector('h2.hP')?.textContent?.trim() ||
            document.title.split('-')[0]?.trim() ||
            'No Subject';

        const senderElement = document.querySelector('.gD') ||
            document.querySelector('[email]') ||
            document.querySelector('.go');

        const senderName = senderElement?.textContent?.trim() || 'Unknown';
        const senderEmail = senderElement?.getAttribute('email') ||
            senderElement?.textContent?.match(/<(.+?)>/)?.[1] ||
            senderElement?.textContent?.trim() || 'Unknown';

        const date = document.querySelector('.g3')?.textContent?.trim() ||
            document.querySelector('.xW')?.textContent?.trim() ||
            'Unknown Date';

        // Check for security indicators in the UI
        const isVerified = !!document.querySelector('[aria-label*="Verified" i], [title*="Verified" i]');
        const viaDomain = document.querySelector('.ajy')?.textContent?.trim() || null;

        const emailData = {
            subject: subject,
            from: senderEmail,
            senderName: senderName,
            date: date,
            body: emailBody.textContent.trim(),
            url: window.location.href,
            emailId: currentEmailId,
            extractedAt: new Date().toISOString(),
            isVerifiedUI: isVerified,
            viaDomain: viaDomain
        };

        console.log('Email extracted:', {
            subject: subject.substring(0, 50) + '...',
            from: senderEmail,
            bodyLength: emailBody.textContent.trim().length
        });

        return JSON.stringify(emailData);

    } catch (error) {
        console.error('Error getting email:', error);
        return null;
    }
}

// Show temporary message
function showTemporaryMessage(message, type = 'info') {
    // Remove existing message
    const existingMsg = document.querySelector('#email-analyzer-msg');
    if (existingMsg) existingMsg.remove();

    const msg = document.createElement('div');
    msg.id = 'email-analyzer-msg';
    msg.textContent = message;

    const colors = {
        error: '#ef4444',
        success: '#10b981',
        info: '#2563eb',
        warning: '#f59e0b'
    };

    msg.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 24px;
        background: ${colors[type] || colors.info};
        color: white;
        border-radius: 8px;
        z-index: 999999;
        font-family: 'Google Sans', Roboto, Arial, sans-serif;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideIn 0.3s ease;
    `;

    // Add animation styles
    if (!document.querySelector('#analyzer-styles')) {
        const style = document.createElement('style');
        style.id = 'analyzer-styles';
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
        `;
        document.head.appendChild(style);
    }

    document.body.appendChild(msg);

    // Remove after 3 seconds
    setTimeout(() => {
        if (msg.parentNode) {
            msg.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (msg.parentNode) {
                    msg.parentNode.removeChild(msg);
                }
            }, 300);
        }
    }, 3000);
}

// Listen for Gmail's navigation
function observeGmailNavigation() {
    // Watch for URL changes
    let lastUrl = window.location.href;

    const checkUrlChange = () => {
        const currentUrl = window.location.href;
        if (currentUrl !== lastUrl) {
            console.log('URL changed:', currentUrl);
            lastUrl = currentUrl;

            // Reset state
            currentEmailId = null;
            buttonInjected = false;
            retryCount = 0;

            // Start checking again
            startChecking();
        }
    };

    // Check URL periodically
    setInterval(checkUrlChange, 1000);

    // Also check on click (Gmail uses lots of click events)
    document.addEventListener('click', () => {
        setTimeout(() => {
            if (window.location.href !== lastUrl) {
                checkUrlChange();
            }
        }, 500);
    });
}

// Start checking for emails
function startChecking() {
    console.log('🔄 Starting email detection...');

    // Initial check
    checkAndInjectButton();

    // Periodic checks
    const checkInterval = setInterval(checkAndInjectButton, CONFIG.checkInterval);

    // Stop after max time (5 minutes)
    setTimeout(() => {
        clearInterval(checkInterval);
        console.log('Stopped periodic checks');
    }, 300000);
}

// Listen for messages from background/popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Content script received:', request.action);

    if (request.action === 'getCurrentEmail') {
        const content = getEmailContent();
        sendResponse({ emailContent: content });
    }

    if (request.action === 'testButton' || request.action === 'ping') {
        // Force button injection
        currentEmailId = null;
        buttonInjected = false;
        setTimeout(() => {
            checkAndInjectButton();
        }, 300);
        sendResponse({ success: true, message: 'Button injection triggered' });
    }

    if (request.action === 'checkEmail') {
        const emailId = getCurrentEmailId();
        sendResponse({
            hasEmail: !!emailId,
            emailId: emailId,
            url: window.location.href
        });
    }

    return true;
});

// Main initialization
function initialize() {
    console.log('🚀 Email Analyzer initialized');

    // Add CSS animations
    if (!document.querySelector('#analyzer-styles')) {
        const style = document.createElement('style');
        style.id = 'analyzer-styles';
        style.textContent = `
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .email-analyzer-btn {
                animation: fadeIn 0.3s ease;
            }
        `;
        document.head.appendChild(style);
    }

    // Start monitoring
    startChecking();

    // Monitor Gmail navigation
    observeGmailNavigation();

    // Also check on DOM changes (Gmail is very dynamic)
    const observer = new MutationObserver(() => {
        if (window._EMAIL_ANALYZER_ID !== _SCRIPT_INST_ID || !isContextValid()) {
            removeButton();
            observer.disconnect();
            return;
        }
        if (!buttonInjected && getCurrentEmailId()) {
            setTimeout(() => {
                checkAndInjectButton();
            }, 300);
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    console.log('✅ All systems ready');
}

// Wait for Gmail to load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// Fallback: if Gmail loads very late
setTimeout(initialize, 3000);

