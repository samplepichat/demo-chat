import { APIClient } from './api.js';
import {
    deriveAllKeyPairs,
    encryptMessage,
    decryptMessage,
    exportPublicKey,
    importPublicKey,
    getPrivateKeyForGeneration,
    getCurrentPublicKey,
    setKeyring,
    getKeyring,
    clearKeyring,
    rotateKeyInKeyring,
    encryptKeyring
} from './crypto.js';
import {
    initGroupChat,
    updateKeyring as updateGroupKeyring,
    loadGroups,
    getSelectedGroup,
    clearGroupSelection,
    sendGroupMessage
} from './groupChat.js';
import {
    initNotifications,
    requestNotificationPermission,
    notifyNewDirectMessage,
    areNotificationsEnabled
} from './notifications.js';

const api = new APIClient();

// Track seen message IDs to detect new messages
let seenMessageIds = new Set();

// Application state
let currentUser = null;
let masterSeed = null;
let keyPairs = [];           // Legacy HD key pairs
let currentKeyring = null;   // New keyring model
let useLegacyMode = false;   // True if using HD keys instead of keyring
let selectedUser = null;
let users = [];
let messages = [];
let refreshInterval = null;
let activeTab = 'contacts';  // 'contacts' or 'groups'

// DOM elements
const currentUsernameEl = document.getElementById('current-username');
const keyGenNumberEl = document.getElementById('key-gen-number');
const lastRotationEl = document.getElementById('last-rotation');
const usersListEl = document.getElementById('users-list');
const messagesContainerEl = document.getElementById('messages-container');
const messageInputContainerEl = document.getElementById('message-input-container');
const chatRecipientNameEl = document.getElementById('chat-recipient-name');
const recipientKeyGenEl = document.getElementById('recipient-key-gen');
const messageInputEl = document.getElementById('message-input');
const sendMessageFormEl = document.getElementById('send-message-form');
const logoutBtnEl = document.getElementById('logout-btn');
const rotateKeyBtnEl = document.getElementById('rotate-key-btn');
const keyDerivationStatusEl = document.getElementById('key-derivation-status');
const statusMessageEl = document.getElementById('status-message');
// Tab elements
const contactsTabBtn = document.getElementById('contacts-tab-btn');
const groupsTabBtn = document.getElementById('groups-tab-btn');
const contactsTabContent = document.getElementById('contacts-tab');
const groupsTabContent = document.getElementById('groups-tab');
// Chat header elements
const directChatHeader = document.getElementById('direct-chat-header');
const groupChatHeader = document.getElementById('group-chat-header');

// Initialize
async function init() {

    await api.init();

    // Check authentication
    if (!api.token) {
        console.error("moving to main site");
        return;
    }

    // Check for keyring (new model) or master seed (legacy mode)
    const keyringJson = sessionStorage.getItem('keyring');
    const masterSeedB64 = sessionStorage.getItem('master_seed');

    if (keyringJson) {
        // New keyring model
        try {
            currentKeyring = JSON.parse(keyringJson);
            setKeyring(currentKeyring);
            useLegacyMode = currentKeyring.legacyMode === true;
        } catch (e) {
            console.error('Failed to parse keyring:', e);
            console.error("moving to main site");
            return;
        }
    } else if (masterSeedB64) {
        // Legacy HD mode fallback
        useLegacyMode = true;
        masterSeed = base64ToArray(masterSeedB64);
    } else {
        console.error("moving to main site");
        return;
    }

    try {
        // Get current user info
        currentUser = await api.getCurrentUser();
        currentUsernameEl.textContent = currentUser.username;
        keyGenNumberEl.textContent = currentUser.key_generation_number;

        const lastRotation = new Date(currentUser.last_key_rotation);
        lastRotationEl.textContent = `Last rotation: ${lastRotation.toLocaleDateString()}`;

        // Initialize keys based on mode
        await initializeKeys();

        // Load users
        await loadUsers();

        // Initialize group chat module
        initGroupChat({
            currentUser: currentUser,
            keyring: currentKeyring,
            useLegacyMode: useLegacyMode,
            keyPairs: keyPairs
        });

        // Initialize notifications
        await initNotifications();

        // Request notification permission (will show prompt if not yet decided)
        if (!areNotificationsEnabled()) {
            // Show a button to request permissions instead of auto-prompting
            showNotificationPrompt();
        }

        // Set up event listeners
        setupEventListeners();

        // Set up tab switching
        setupTabs();

        // Start auto-refresh for contacts
        refreshInterval = setInterval(refreshConversation, 5000); // Refresh every 5 seconds

    } catch (error) {
        console.error('Initialization error:', error);
        alert('Failed to initialize: ' + error.message);
        console.error("moving to main site");
    }
}

async function initializeKeys() {
    showStatus('Initializing encryption keys...');

    try {
        if (useLegacyMode && masterSeed) {
            // Legacy HD key derivation
            keyPairs = await deriveAllKeyPairs(masterSeed, currentUser.key_generation_number);
            console.log(`Derived ${keyPairs.length} HD key pairs (generation 0 to ${currentUser.key_generation_number})`);

            // Upload current public key to backend
            const currentKeyPair = keyPairs[keyPairs.length - 1];
            const publicKeyB64 = await exportPublicKey(currentKeyPair.publicKey);

            showStatus('Uploading public key...');
            await api.updatePublicKey(publicKeyB64);
        } else if (currentKeyring && currentKeyring.identityKeys) {
            // New keyring model - keys are already in the keyring
            console.log(`Using keyring with ${currentKeyring.identityKeys.length} key(s)`);

            // Public key should already be uploaded during login
            // But verify it's current
            const publicKeyB64 = getCurrentPublicKey(currentKeyring);
            showStatus('Verifying public key...');
            await api.updatePublicKey(publicKeyB64);
        }

        console.log('Keys initialized successfully');

    } catch (error) {
        console.error('Key initialization error:', error);
        console.error('Error stack:', error.stack);
        throw new Error('Failed to initialize encryption keys: ' + error.message);
    } finally {
        hideStatus();
    }
}

async function loadUsers() {
    try {
        users = await api.getUsers();
        renderUsers();
    } catch (error) {
        console.error('Failed to load users:', error);
        users = [];
        usersListEl.innerHTML = '<div class="loading-users">Failed to load users</div>';
    }
}

function renderUsers() {
    if (!users || users.length === 0) {
        usersListEl.innerHTML = '<div class="loading-users">No other users yet</div>';
        return;
    }

    usersListEl.innerHTML = users.map(user => `
        <div class="user-item ${selectedUser && selectedUser.id === user.id ? 'active' : ''}" data-user-id="${user.id}">
            <div class="username">${escapeHtml(user.username)}</div>
        </div>
    `).join('');

    // Add click handlers
    document.querySelectorAll('.user-item').forEach(item => {
        item.addEventListener('click', () => {
            const userId = parseInt(item.dataset.userId);
            const user = users.find(u => u.id === userId);
            if (user) {
                selectUser(user);
            }
        });
    });
}

async function selectUser(user) {
    selectedUser = user;
    renderUsers();

    // Show direct chat header, hide group chat header
    if (directChatHeader) {
        directChatHeader.style.display = 'flex';
    }
    if (groupChatHeader) {
        groupChatHeader.style.display = 'none';
    }

    chatRecipientNameEl.textContent = user.username;
    messageInputContainerEl.style.display = 'flex';

    // Get user's current key generation
    try {
        const keyInfo = await api.getUserPublicKeyInfo(user.username);
        recipientKeyGenEl.textContent = `Key Generation: ${keyInfo.key_generation_number}`;
    } catch (error) {
        console.error('Failed to get user key info:', error);
    }

    // Load conversation
    await loadConversation();
}

async function loadConversation() {
    if (!selectedUser) return;

    try {
        const newMessages = await api.getConversation(selectedUser.username);

        // Check for new messages to notify about
        if (messages.length > 0 && newMessages.length > messages.length) {
            const newMsgCount = newMessages.length - messages.length;
            const latestMessages = newMessages.slice(-newMsgCount);

            for (const msg of latestMessages) {
                // Only notify for received messages we haven't seen
                if (msg.sender_id !== currentUser.user_id && !seenMessageIds.has(msg.id)) {
                    // Try to decrypt for preview
                    let preview = null;
                    try {
                        const keyGenUsed = msg.key_generation_used;
                        const privateKey = await getPrivateKey(keyGenUsed);
                        if (privateKey) {
                            preview = await decryptMessage(
                                msg.encrypted_content,
                                msg.ephemeral_public_key,
                                msg.nonce,
                                privateKey
                            );
                        }
                    } catch (e) {
                        // Decryption failed, notification will show generic text
                    }
                    notifyNewDirectMessage(msg.sender_username, preview);
                }
            }
        }

        // Update seen message IDs
        for (const msg of newMessages) {
            seenMessageIds.add(msg.id);
        }

        messages = newMessages;
        await renderMessages();
    } catch (error) {
        console.error('Failed to load conversation:', error);
        messages = [];
        messagesContainerEl.innerHTML = '<div class="no-conversation">Failed to load messages</div>';
    }
}

async function renderMessages() {
    if (!messages || messages.length === 0) {
        messagesContainerEl.innerHTML = '<div class="no-conversation">No messages yet. Start the conversation!</div>';
        return;
    }

    const messagesHTML = [];

    for (const msg of messages) {
        const isSent = msg.sender_id === currentUser.user_id;
        const messageClass = isSent ? 'sent' : 'received';

        let decryptedText = '[Encrypted]';

        try {
            if (!isSent) {
                // Decrypt received message using our private key
                const keyGenUsed = msg.key_generation_used;
                const privateKey = await getPrivateKey(keyGenUsed);
                if (privateKey) {
                    decryptedText = await decryptMessage(
                        msg.encrypted_content,
                        msg.ephemeral_public_key,
                        msg.nonce,
                        privateKey
                    );
                } else {
                    decryptedText = '[Key not available - generation mismatch]';
                }
            } else {
                // Decrypt sent message using sender's encrypted copy
                const senderKeyGenUsed = msg.sender_key_generation_used;
                const privateKey = await getPrivateKey(senderKeyGenUsed);
                if (privateKey) {
                    decryptedText = await decryptMessage(
                        msg.sender_encrypted_content,
                        msg.sender_ephemeral_public_key,
                        msg.sender_nonce,
                        privateKey
                    );
                } else {
                    decryptedText = '[Key not available - generation mismatch]';
                }
            }
        } catch (error) {
            console.error('Decryption error:', error);
            decryptedText = '[Decryption failed]';
        }

        const timestamp = new Date(msg.timestamp).toLocaleTimeString();

        messagesHTML.push(`
            <div class="message ${messageClass}">
                <div class="message-bubble">${escapeHtml(decryptedText)}</div>
                <div class="message-meta">
                    <span>${timestamp}</span>
                    ${isSent ? '<span>🔒</span>' : `<span>🔒 (Gen ${msg.key_generation_used})</span>`}
                </div>
            </div>
        `);
    }

    messagesContainerEl.innerHTML = messagesHTML.join('');

    // Scroll to bottom
    messagesContainerEl.scrollTop = messagesContainerEl.scrollHeight;
}

/**
 * Get private key for a specific generation (works with both keyring and legacy modes)
 */
async function getPrivateKey(generation) {
    if (useLegacyMode && keyPairs.length > 0) {
        // Legacy HD mode
        if (generation < keyPairs.length) {
            return keyPairs[generation].privateKey;
        }
        return null;
    } else if (currentKeyring && currentKeyring.identityKeys) {
        // Keyring mode
        try {
            return await getPrivateKeyForGeneration(currentKeyring, generation);
        } catch (e) {
            console.error(`No key for generation ${generation}:`, e);
            return null;
        }
    }
    return null;
}

async function refreshConversation() {
    if (selectedUser) {
        await loadConversation();
    }
}

async function sendMessage(e) {
    e.preventDefault();

    const messageText = messageInputEl.value.trim();
    if (!messageText) return;

    // Check if we're in group mode
    const selectedGroup = getSelectedGroup();
    if (selectedGroup) {
        try {
            await sendGroupMessage(messageText);
            messageInputEl.value = '';
        } catch (error) {
            console.error('Failed to send group message:', error);
            alert('Failed to send message: ' + error.message);
        }
        return;
    }

    // Direct message mode
    if (!selectedUser) return;

    try {
        // Get recipient's current public key info from backend
        const recipientKeyInfo = await api.getUserPublicKeyInfo(selectedUser.username);

        // Check if recipient has uploaded their public key
        if (!recipientKeyInfo.current_public_key) {
            alert('Recipient has not uploaded their public key yet. They need to login first.');
            return;
        }

        // Import recipient's actual public key
        const recipientPublicKey = await importPublicKey(recipientKeyInfo.current_public_key);

        // Encrypt message for recipient using recipient's public key
        const encryptedForRecipient = await encryptMessage(messageText, recipientPublicKey);

        // Get sender's own public key to encrypt for themselves
        let senderPublicKey;
        let senderKeyGeneration;

        if (useLegacyMode && keyPairs.length > 0) {
            // Legacy HD mode
            const senderKeyPair = keyPairs[keyPairs.length - 1];
            senderPublicKey = senderKeyPair.publicKey;
            senderKeyGeneration = currentUser.key_generation_number;
        } else if (currentKeyring && currentKeyring.identityKeys) {
            // Keyring mode
            senderKeyGeneration = currentKeyring.identityKeys.length - 1;
            const senderPublicKeyB64 = getCurrentPublicKey(currentKeyring);
            senderPublicKey = await importPublicKey(senderPublicKeyB64);
        } else {
            throw new Error('No keys available for encryption');
        }

        // Encrypt message for sender using sender's own public key
        const encryptedForSender = await encryptMessage(messageText, senderPublicKey);

        // Send to backend with both encrypted versions
        await api.sendMessage(
            selectedUser.username,
            encryptedForRecipient.ciphertext,
            encryptedForSender.ciphertext,
            recipientKeyInfo.key_generation_number,
            senderKeyGeneration,
            encryptedForRecipient.ephemeralPublicKey,
            encryptedForSender.ephemeralPublicKey,
            encryptedForRecipient.nonce,
            encryptedForSender.nonce
        );

        // Clear input
        messageInputEl.value = '';

        // Refresh conversation
        await loadConversation();

    } catch (error) {
        console.error('Failed to send message:', error);
        alert('Failed to send message: ' + error.message);
    }
}

function setupTabs() {
    if (contactsTabBtn) {
        contactsTabBtn.addEventListener('click', () => switchTab('contacts'));
    }
    if (groupsTabBtn) {
        groupsTabBtn.addEventListener('click', () => switchTab('groups'));
    }
}

function switchTab(tab) {
    activeTab = tab;

    // Update tab buttons
    if (contactsTabBtn) {
        contactsTabBtn.classList.toggle('active', tab === 'contacts');
    }
    if (groupsTabBtn) {
        groupsTabBtn.classList.toggle('active', tab === 'groups');
    }

    // Update tab content
    if (contactsTabContent) {
        contactsTabContent.style.display = tab === 'contacts' ? 'block' : 'none';
    }
    if (groupsTabContent) {
        groupsTabContent.style.display = tab === 'groups' ? 'block' : 'none';
    }

    // Update chat headers
    if (tab === 'contacts') {
        // Clear group selection
        clearGroupSelection();
        if (groupChatHeader) {
            groupChatHeader.style.display = 'none';
        }
        // Show direct chat header if a user is selected
        if (directChatHeader && selectedUser) {
            directChatHeader.style.display = 'flex';
        }
    } else {
        // Clear contact selection
        selectedUser = null;
        renderUsers();
        if (directChatHeader) {
            directChatHeader.style.display = 'none';
        }
        // Clear messages when switching to groups
        if (messagesContainerEl) {
            messagesContainerEl.innerHTML = '<div class="no-conversation">Select a group to start chatting</div>';
        }
        if (messageInputContainerEl) {
            messageInputContainerEl.style.display = 'none';
        }
        // Reload groups
        loadGroups();
    }
}

function setupEventListeners() {
    sendMessageFormEl.addEventListener('submit', sendMessage);

    logoutBtnEl.addEventListener('click', async () => {
        if (confirm('Are you sure you want to logout?')) {
            try {
                await api.logout();
            } catch (error) {
                console.error('Logout error:', error);
            } finally {
                // Clear keyring from memory
                clearKeyring();
                currentKeyring = null;
                keyPairs = [];
                sessionStorage.clear();
                console.error("moving to main site");
            }
        }
    });

    rotateKeyBtnEl.addEventListener('click', async () => {
        if (confirm('Rotate your encryption keys? This will generate a new key generation.')) {
            try {
                if (!useLegacyMode && currentKeyring) {
                    // Keyring mode: rotate key in keyring and re-upload
                    const password = prompt('Enter your password to rotate keys:');
                    if (!password) return;

                    showStatus('Rotating keys...');

                    // Add new key to keyring
                    currentKeyring = await rotateKeyInKeyring(currentKeyring);

                    // Encrypt and upload new keyring
                    const encrypted = await encryptKeyring(currentKeyring, password);
                    await api.rotateKeyring(encrypted.encryptedKeyring, encrypted.nonce, encrypted.salt);

                    // Update public key on server
                    const newPublicKey = getCurrentPublicKey(currentKeyring);
                    await api.updatePublicKey(newPublicKey);

                    // Update session storage
                    sessionStorage.setItem('keyring', JSON.stringify(currentKeyring));
                    setKeyring(currentKeyring);
                    updateGroupKeyring(currentKeyring);

                    hideStatus();
                    alert('Key rotated successfully! Reloading...');
                    location.reload();
                } else {
                    // Legacy mode: just rotate on server
                    await api.rotateKey();
                    alert('Key rotated successfully! Reloading...');
                    location.reload();
                }
            } catch (error) {
                hideStatus();
                console.error('Key rotation error:', error);
                alert('Failed to rotate key: ' + error.message);
            }
        }
    });
}

function showStatus(message) {
    statusMessageEl.textContent = message;
    keyDerivationStatusEl.style.display = 'flex';
}

function hideStatus() {
    keyDerivationStatusEl.style.display = 'none';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function base64ToArray(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// Notification permission prompt
function showNotificationPrompt() {
    // Check if we've already shown the prompt this session
    if (sessionStorage.getItem('notification_prompt_shown')) {
        return;
    }

    // Create notification prompt banner
    const banner = document.createElement('div');
    banner.id = 'notification-prompt';
    banner.className = 'notification-prompt';
    banner.innerHTML = `
        <span>Enable notifications to get alerts for new messages</span>
        <div class="notification-prompt-actions">
            <button id="enable-notifications-btn" class="btn btn-small btn-primary">Enable</button>
            <button id="dismiss-notifications-btn" class="btn btn-small">Later</button>
        </div>
    `;

    document.body.appendChild(banner);

    document.getElementById('enable-notifications-btn').addEventListener('click', async () => {
        const granted = await requestNotificationPermission();
        if (granted) {
            banner.remove();
        } else {
            banner.querySelector('span').textContent = 'Notifications blocked. Enable in browser settings.';
            setTimeout(() => banner.remove(), 3000);
        }
    });

    document.getElementById('dismiss-notifications-btn').addEventListener('click', () => {
        banner.remove();
        sessionStorage.setItem('notification_prompt_shown', 'true');
    });
}

// Cleanup on unload
window.addEventListener('beforeunload', () => {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});

// Start the app
init();
