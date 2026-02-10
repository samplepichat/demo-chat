// Group chat module
// Handles group creation, messaging, member management, and key rotation

import { APIClient } from './api.js';
import {
    generateGroupKey,
    encryptGroupKeyForMember,
    decryptGroupKey,
    encryptGroupMessage,
    decryptGroupMessage
} from './groupCrypto.js';
import {
    getPrivateKeyForGeneration,
    getKeyring
} from './crypto.js';
import {
    notifyNewGroupMessage,
    notifyAddedToGroup
} from './notifications.js';

const api = new APIClient();

// Track seen message IDs for notifications
let seenGroupMessageIds = new Set();
// Track known group IDs to detect new group memberships
let knownGroupIds = new Set();

// ============================================
// State
// ============================================

let groups = [];
let selectedGroup = null;
let groupMessages = [];
let groupKeys = new Map(); // groupId -> { [keyGen]: CryptoKey }
let groupRefreshInterval = null;

// References to external state (set via init)
let currentUser = null;
let currentKeyring = null;
let useLegacyMode = false;
let keyPairs = [];

// DOM element references (set via init)
let elements = {};

// ============================================
// Initialization
// ============================================

/**
 * Initialize the group chat module
 * @param {object} config - Configuration object with user info and DOM elements
 */
export function initGroupChat(config) {
    currentUser = config.currentUser;
    currentKeyring = config.keyring;
    useLegacyMode = config.useLegacyMode || false;
    keyPairs = config.keyPairs || [];

    elements = {
        groupsList: document.getElementById('groups-list'),
        createGroupBtn: document.getElementById('create-group-btn'),
        createGroupModal: document.getElementById('create-group-modal'),
        createGroupForm: document.getElementById('create-group-form'),
        groupNameInput: document.getElementById('group-name-input'),
        memberSelectList: document.getElementById('member-select-list'),
        groupChatHeader: document.getElementById('group-chat-header'),
        groupName: document.getElementById('group-name'),
        groupMemberCount: document.getElementById('group-member-count'),
        manageMembersBtn: document.getElementById('manage-members-btn'),
        leaveGroupBtn: document.getElementById('leave-group-btn'),
        manageMembersModal: document.getElementById('manage-members-modal'),
        currentMembersList: document.getElementById('current-members-list'),
        addMemberSelect: document.getElementById('add-member-select'),
        addMemberBtn: document.getElementById('add-member-btn'),
        messagesContainer: document.getElementById('messages-container'),
        sendMessageForm: document.getElementById('send-message-form'),
        messageInput: document.getElementById('message-input'),
    };

    setupEventListeners();
    loadGroups();
}

/**
 * Update keyring reference (called when keyring changes)
 */
export function updateKeyring(keyring) {
    currentKeyring = keyring;
}

/**
 * Get the currently selected group
 */
export function getSelectedGroup() {
    return selectedGroup;
}

/**
 * Clear selection (when switching to contacts)
 */
function clearGroupSelection() {
    selectedGroup = null;
    if (elements.groupChatHeader) {
        elements.groupChatHeader.style.display = 'none';
    }
    stopGroupRefresh();
}

// ============================================
// Event Listeners
// ============================================

function setupEventListeners() {
    // Create group button
    if (elements.createGroupBtn) {
        elements.createGroupBtn.addEventListener('click', openCreateGroupModal);
    }

    // Create group form
    if (elements.createGroupForm) {
        elements.createGroupForm.addEventListener('submit', handleCreateGroup);
    }

    // Manage members button
    if (elements.manageMembersBtn) {
        elements.manageMembersBtn.addEventListener('click', openManageMembersModal);
    }

    // Leave group button
    if (elements.leaveGroupBtn) {
        elements.leaveGroupBtn.addEventListener('click', handleLeaveGroup);
    }

    // Add member button
    if (elements.addMemberBtn) {
        elements.addMemberBtn.addEventListener('click', handleAddMember);
    }

    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === elements.createGroupModal) {
            closeCreateGroupModal();
        }
        if (e.target === elements.manageMembersModal) {
            closeManageMembersModal();
        }
    });
}

// ============================================
// Group List
// ============================================

/**
 * Load user's groups from the server
 */
async function loadGroups() {
    try {
        const newGroups = await api.getGroups() || [];

        // Check for new group memberships (user was added to a group)
        for (const group of newGroups) {
            if (!knownGroupIds.has(group.id)) {
                // This is a new group we weren't in before
                // Only notify if we have existing known groups (not first load)
                if (knownGroupIds.size > 0) {
                    notifyAddedToGroup(group.name);
                }
                knownGroupIds.add(group.id);
            }
        }

        // Check for removed groups (user was removed)
        const newGroupIds = new Set(newGroups.map(g => g.id));
        for (const oldGroupId of knownGroupIds) {
            if (!newGroupIds.has(oldGroupId)) {
                knownGroupIds.delete(oldGroupId);
                // Could notify about removal here if desired
            }
        }

        groups = newGroups;
        renderGroups();
    } catch (error) {
        console.error('Failed to load groups:', error);
        groups = [];
        if (elements.groupsList) {
            elements.groupsList.innerHTML = '<div class="loading-groups">Failed to load groups</div>';
        }
    }
}

function renderGroups() {
    if (!elements.groupsList) return;

    if (!groups || groups.length === 0) {
        elements.groupsList.innerHTML = '<div class="no-groups">No groups yet</div>';
        return;
    }

    elements.groupsList.innerHTML = groups.map(group => `
        <div class="group-item ${selectedGroup && selectedGroup.id === group.id ? 'active' : ''}" data-group-id="${group.id}">
            <div class="group-name">${escapeHtml(group.name)}</div>
            <div class="group-meta">${group.member_count} member${group.member_count !== 1 ? 's' : ''}</div>
        </div>
    `).join('');

    // Add click handlers
    document.querySelectorAll('.group-item').forEach(item => {
        item.addEventListener('click', () => {
            const groupId = parseInt(item.dataset.groupId);
            const group = groups.find(g => g.id === groupId);
            if (group) {
                selectGroup(group);
            }
        });
    });
}

// ============================================
// Group Selection
// ============================================

/**
 * Select a group and load its messages
 */
async function selectGroup(group) {
    selectedGroup = group;
    renderGroups();

    // Show group chat header and hide direct chat header
    const directChatHeader = document.getElementById('direct-chat-header');
    if (directChatHeader) {
        directChatHeader.style.display = 'none';
    }
    if (elements.groupChatHeader) {
        elements.groupChatHeader.style.display = 'flex';
    }
    if (elements.groupName) {
        elements.groupName.textContent = group.name;
    }
    if (elements.groupMemberCount) {
        elements.groupMemberCount.textContent = `${group.member_count} members`;
    }

    // Show message input
    const messageInputContainer = document.getElementById('message-input-container');
    if (messageInputContainer) {
        messageInputContainer.style.display = 'flex';
    }

    // Load full group details including encrypted key
    try {
        const groupDetails = await api.getGroup(group.id);
        selectedGroup = { ...selectedGroup, ...groupDetails };

        // Decrypt and cache the group key
        await decryptAndCacheGroupKeys(groupDetails);

        // Load messages
        await loadGroupMessages();

        // Start auto-refresh
        startGroupRefresh();

    } catch (error) {
        console.error('Failed to load group details:', error);
        if (elements.messagesContainer) {
            elements.messagesContainer.innerHTML = '<div class="error">Failed to load group</div>';
        }
    }
}

// ============================================
// Group Key Management
// ============================================

/**
 * Decrypt and cache group keys from membership data
 */
async function decryptAndCacheGroupKeys(groupDetails) {
    const groupId = groupDetails.id;

    // Initialize cache for this group if needed
    if (!groupKeys.has(groupId)) {
        groupKeys.set(groupId, {});
    }
    const keyCache = groupKeys.get(groupId);

    // Decrypt current key
    if (groupDetails.membership) {
        const m = groupDetails.membership;
        try {
            const privateKey = await getPrivateKey(m.user_key_generation);
            if (privateKey) {
                const groupKey = await decryptGroupKey(
                    m.encrypted_key,
                    m.ephemeral_public_key,
                    m.nonce,
                    privateKey
                );
                keyCache[m.key_generation] = groupKey;
            }
        } catch (error) {
            console.error(`Failed to decrypt current group key (gen ${m.key_generation}):`, error);
        }
    }

    // Decrypt historical keys
    if (groupDetails.key_history) {
        for (const kh of groupDetails.key_history) {
            if (keyCache[kh.key_generation]) continue; // Already cached

            try {
                const privateKey = await getPrivateKey(kh.user_key_generation);
                if (privateKey) {
                    const groupKey = await decryptGroupKey(
                        kh.encrypted_key,
                        kh.ephemeral_public_key,
                        kh.nonce,
                        privateKey
                    );
                    keyCache[kh.key_generation] = groupKey;
                }
            } catch (error) {
                console.error(`Failed to decrypt historical group key (gen ${kh.key_generation}):`, error);
            }
        }
    }
}

/**
 * Get the group key for a specific generation
 */
async function getGroupKeyForGeneration(groupId, generation) {
    const keyCache = groupKeys.get(groupId);
    if (keyCache && keyCache[generation]) {
        return keyCache[generation];
    }

    // Try to fetch group details and decrypt
    try {
        const groupDetails = await api.getGroup(groupId);
        await decryptAndCacheGroupKeys(groupDetails);

        const newCache = groupKeys.get(groupId);
        if (newCache && newCache[generation]) {
            return newCache[generation];
        }
    } catch (error) {
        console.error(`Failed to get group key for generation ${generation}:`, error);
    }

    return null;
}

/**
 * Get private key for a specific generation (works with both keyring and legacy modes)
 */
async function getPrivateKey(generation) {
    if (useLegacyMode && keyPairs.length > 0) {
        if (generation < keyPairs.length) {
            return keyPairs[generation].privateKey;
        }
        return null;
    } else if (currentKeyring && currentKeyring.identityKeys) {
        try {
            return await getPrivateKeyForGeneration(currentKeyring, generation);
        } catch (e) {
            console.error(`No key for generation ${generation}:`, e);
            return null;
        }
    }
    return null;
}

// ============================================
// Group Messages
// ============================================

/**
 * Load messages for the selected group
 */
async function loadGroupMessages() {
    if (!selectedGroup) return;

    try {
        const newMessages = await api.getGroupMessages(selectedGroup.id) || [];

        // Check for new messages to notify about
        for (const msg of newMessages) {
            // Only notify for messages from others that we haven't seen
            if (msg.sender_id !== currentUser.user_id && !seenGroupMessageIds.has(msg.id)) {
                // Try to decrypt for preview
                let preview = null;
                try {
                    const groupKey = await getGroupKeyForGeneration(selectedGroup.id, msg.key_generation);
                    if (groupKey) {
                        preview = await decryptGroupMessage(msg.ciphertext, msg.nonce, groupKey);
                    }
                } catch (e) {
                    // Decryption failed, notification will show generic text
                }
                notifyNewGroupMessage(selectedGroup.name, msg.sender_username, preview);
            }
            seenGroupMessageIds.add(msg.id);
        }

        groupMessages = newMessages;
        await renderGroupMessages();
    } catch (error) {
        console.error('Failed to load group messages:', error);
        groupMessages = [];
        if (elements.messagesContainer) {
            elements.messagesContainer.innerHTML = '<div class="error">Failed to load messages</div>';
        }
    }
}

async function renderGroupMessages() {
    if (!elements.messagesContainer) return;

    if (!groupMessages || groupMessages.length === 0) {
        elements.messagesContainer.innerHTML = '<div class="no-conversation">No messages yet. Start the conversation!</div>';
        return;
    }

    const messagesHTML = [];

    for (const msg of groupMessages) {
        const isSent = msg.sender_id === currentUser.user_id;
        const messageClass = isSent ? 'sent' : 'received';

        let decryptedText = '[Encrypted]';

        try {
            const groupKey = await getGroupKeyForGeneration(selectedGroup.id, msg.key_generation);
            if (groupKey) {
                decryptedText = await decryptGroupMessage(
                    msg.ciphertext,
                    msg.nonce,
                    groupKey
                );
            } else {
                decryptedText = '[Key not available]';
            }
        } catch (error) {
            console.error('Decryption error:', error);
            decryptedText = '[Decryption failed]';
        }

        const timestamp = new Date(msg.timestamp).toLocaleTimeString();

        messagesHTML.push(`
            <div class="message ${messageClass}">
                ${!isSent ? `<div class="message-sender">${escapeHtml(msg.sender_username)}</div>` : ''}
                <div class="message-bubble">${escapeHtml(decryptedText)}</div>
                <div class="message-meta">
                    <span>${timestamp}</span>
                    <span title="Key generation ${msg.key_generation}">&#128274;</span>
                </div>
            </div>
        `);
    }

    elements.messagesContainer.innerHTML = messagesHTML.join('');
    elements.messagesContainer.scrollTop = elements.messagesContainer.scrollHeight;
}

/**
 * Send a message to the selected group
 */
async function sendGroupMessage(messageText) {
    if (!selectedGroup || !messageText.trim()) return;

    try {
        // Get the current group key
        const currentKeyGen = selectedGroup.current_key_gen;
        const groupKey = await getGroupKeyForGeneration(selectedGroup.id, currentKeyGen);

        if (!groupKey) {
            throw new Error('Group key not available');
        }

        // Encrypt the message
        const encrypted = await encryptGroupMessage(messageText, groupKey);

        // Send to server
        await api.sendGroupMessage(
            selectedGroup.id,
            encrypted.ciphertext,
            encrypted.nonce,
            currentKeyGen
        );

        // Refresh messages
        await loadGroupMessages();

    } catch (error) {
        console.error('Failed to send group message:', error);
        throw error;
    }
}

function startGroupRefresh() {
    stopGroupRefresh();
    groupRefreshInterval = setInterval(async () => {
        if (selectedGroup) {
            await loadGroupMessages();
        }
    }, 5000);
}

function stopGroupRefresh() {
    if (groupRefreshInterval) {
        clearInterval(groupRefreshInterval);
        groupRefreshInterval = null;
    }
}

// ============================================
// Group Creation
// ============================================

async function openCreateGroupModal() {
    if (!elements.createGroupModal) return;

    // Load users for member selection
    try {
        const users = await api.getUsers() || [];

        if (elements.memberSelectList) {
            elements.memberSelectList.innerHTML = users.map(user => `
                <label class="member-checkbox">
                    <input type="checkbox" name="members" value="${user.id}" data-username="${escapeHtml(user.username)}">
                    <span>${escapeHtml(user.username)}</span>
                </label>
            `).join('');
        }

        elements.createGroupModal.style.display = 'flex';
    } catch (error) {
        console.error('Failed to load users:', error);
        alert('Failed to load users');
    }
}

function closeCreateGroupModal() {
    if (elements.createGroupModal) {
        elements.createGroupModal.style.display = 'none';
    }
    if (elements.createGroupForm) {
        elements.createGroupForm.reset();
    }
}

async function handleCreateGroup(e) {
    e.preventDefault();

    const name = elements.groupNameInput?.value.trim();
    if (!name) {
        alert('Please enter a group name');
        return;
    }

    // Get selected members
    const checkboxes = document.querySelectorAll('input[name="members"]:checked');
    const selectedUserIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

    // Add current user
    if (!selectedUserIds.includes(currentUser.user_id)) {
        selectedUserIds.push(currentUser.user_id);
    }

    if (selectedUserIds.length < 2) {
        alert('Please select at least one other member');
        return;
    }

    try {
        // Generate group key
        const groupKey = await generateGroupKey();

        // Get public keys for all members and encrypt the group key for each
        const memberKeys = [];

        for (const userId of selectedUserIds) {
            let publicKey, userKeyGen;

            if (userId === currentUser.user_id) {
                // Use current user's own key
                if (currentKeyring && currentKeyring.identityKeys) {
                    const latestKey = currentKeyring.identityKeys[currentKeyring.identityKeys.length - 1];
                    publicKey = latestKey.publicKey;
                    userKeyGen = currentKeyring.identityKeys.length - 1;
                } else if (keyPairs.length > 0) {
                    const exported = await crypto.subtle.exportKey('raw', keyPairs[keyPairs.length - 1].publicKey);
                    publicKey = arrayBufferToBase64(exported);
                    userKeyGen = currentUser.key_generation_number;
                }
            } else {
                // Fetch other user's public key
                const users = await api.getUsers();
                const user = users.find(u => u.id === userId);
                if (user) {
                    const keyInfo = await api.getUserPublicKeyInfo(user.username);
                    publicKey = keyInfo.current_public_key;
                    userKeyGen = keyInfo.key_generation_number;
                }
            }

            if (!publicKey) {
                alert(`Could not get public key for user ${userId}`);
                return;
            }

            const encrypted = await encryptGroupKeyForMember(groupKey, publicKey);

            memberKeys.push({
                user_id: userId,
                encrypted_key: encrypted.encryptedKey,
                ephemeral_public_key: encrypted.ephemeralPublicKey,
                nonce: encrypted.nonce,
                user_key_generation: userKeyGen
            });
        }

        // Create group
        await api.createGroup(name, memberKeys);

        closeCreateGroupModal();
        await loadGroups();

    } catch (error) {
        console.error('Failed to create group:', error);
        alert('Failed to create group: ' + error.message);
    }
}

// ============================================
// Member Management
// ============================================

async function openManageMembersModal() {
    if (!selectedGroup || !elements.manageMembersModal) return;

    try {
        // Load current members
        const members = await api.getGroupMembers(selectedGroup.id) || [];

        // Render current members
        if (elements.currentMembersList) {
            const isAdmin = members.find(m => m.user_id === currentUser.user_id)?.role === 'admin';

            elements.currentMembersList.innerHTML = members.map(member => {
                const canRemove = isAdmin && member.user_id !== currentUser.user_id;
                const canPromote = isAdmin && member.role !== 'admin';

                return `
                    <div class="member-item">
                        <span class="member-name">
                            ${escapeHtml(member.username)}
                            ${member.role === 'admin' ? '<span class="admin-badge">Admin</span>' : ''}
                        </span>
                        <div class="member-actions">
                            ${canPromote ? `<button class="btn btn-small" onclick="window.groupChat.promoteMember(${member.user_id})">Promote</button>` : ''}
                            ${canRemove ? `<button class="btn btn-small btn-danger" onclick="window.groupChat.removeMember(${member.user_id})">Remove</button>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Load users for add member dropdown
        if (elements.addMemberSelect) {
            const allUsers = await api.getUsers() || [];
            const memberIds = members.map(m => m.user_id);
            const nonMembers = allUsers.filter(u => !memberIds.includes(u.id));

            elements.addMemberSelect.innerHTML = nonMembers.length
                ? nonMembers.map(user => `<option value="${user.id}">${escapeHtml(user.username)}</option>`).join('')
                : '<option value="">No users available</option>';

            elements.addMemberBtn.disabled = nonMembers.length === 0;
        }

        elements.manageMembersModal.style.display = 'flex';

    } catch (error) {
        console.error('Failed to load members:', error);
        alert('Failed to load members');
    }
}

function closeManageMembersModal() {
    if (elements.manageMembersModal) {
        elements.manageMembersModal.style.display = 'none';
    }
}

async function handleAddMember() {
    if (!selectedGroup || !elements.addMemberSelect) return;

    const userId = parseInt(elements.addMemberSelect.value);
    if (!userId) return;

    try {
        // Get the user's public key
        const users = await api.getUsers();
        const user = users.find(u => u.id === userId);
        if (!user) {
            alert('User not found');
            return;
        }

        const keyInfo = await api.getUserPublicKeyInfo(user.username);
        if (!keyInfo.current_public_key) {
            alert('User has not set up their keys yet');
            return;
        }

        // Get the current group key
        const currentKeyGen = selectedGroup.current_key_gen;
        const groupKey = await getGroupKeyForGeneration(selectedGroup.id, currentKeyGen);

        if (!groupKey) {
            alert('Cannot access group key');
            return;
        }

        // Encrypt the group key for the new member
        const encrypted = await encryptGroupKeyForMember(groupKey, keyInfo.current_public_key);

        // Add member via API
        await api.addGroupMember(selectedGroup.id, {
            user_id: userId,
            encrypted_key: encrypted.encryptedKey,
            ephemeral_public_key: encrypted.ephemeralPublicKey,
            nonce: encrypted.nonce,
            user_key_generation: keyInfo.key_generation_number
        });

        // Refresh
        closeManageMembersModal();
        await loadGroups();
        if (selectedGroup) {
            const group = groups.find(g => g.id === selectedGroup.id);
            if (group) {
                await selectGroup(group);
            }
        }

    } catch (error) {
        console.error('Failed to add member:', error);
        alert('Failed to add member: ' + error.message);
    }
}

/**
 * Remove a member and rotate the group key
 */
async function removeMember(userId) {
    if (!selectedGroup) return;

    if (!confirm('Remove this member? This will rotate the group key.')) return;

    try {
        // Remove the member
        await api.removeGroupMember(selectedGroup.id, userId);

        // Rotate the group key
        await rotateGroupKey();

        // Refresh
        closeManageMembersModal();
        await loadGroups();
        if (selectedGroup) {
            const group = groups.find(g => g.id === selectedGroup.id);
            if (group) {
                await selectGroup(group);
            }
        }

    } catch (error) {
        console.error('Failed to remove member:', error);
        alert('Failed to remove member: ' + error.message);
    }
}

/**
 * Promote a member to admin
 */
async function promoteMember(userId) {
    if (!selectedGroup) return;

    try {
        await api.promoteMember(selectedGroup.id, userId);
        await openManageMembersModal(); // Refresh modal
    } catch (error) {
        console.error('Failed to promote member:', error);
        alert('Failed to promote member: ' + error.message);
    }
}

/**
 * Rotate the group key (after member removal)
 */
async function rotateGroupKey() {
    if (!selectedGroup) return;

    try {
        // Generate a new group key
        const newGroupKey = await generateGroupKey();

        // Get all current members
        const members = await api.getGroupMembers(selectedGroup.id) || [];

        // Encrypt the new key for all members
        const memberKeys = [];

        for (const member of members) {
            const encrypted = await encryptGroupKeyForMember(newGroupKey, member.current_public_key);

            memberKeys.push({
                user_id: member.user_id,
                encrypted_key: encrypted.encryptedKey,
                ephemeral_public_key: encrypted.ephemeralPublicKey,
                nonce: encrypted.nonce,
                user_key_generation: member.key_generation_number
            });
        }

        // Rotate via API
        await api.rotateGroupKey(selectedGroup.id, memberKeys);

        // Clear cached keys for this group (will be re-fetched)
        groupKeys.delete(selectedGroup.id);

    } catch (error) {
        console.error('Failed to rotate group key:', error);
        throw error;
    }
}

async function handleLeaveGroup() {
    if (!selectedGroup) return;

    if (!confirm(`Leave group "${selectedGroup.name}"?`)) return;

    try {
        await api.leaveGroup(selectedGroup.id);

        // Clear selection
        selectedGroup = null;
        groupKeys.delete(selectedGroup?.id);
        stopGroupRefresh();

        if (elements.groupChatHeader) {
            elements.groupChatHeader.style.display = 'none';
        }
        if (elements.messagesContainer) {
            elements.messagesContainer.innerHTML = '<div class="no-conversation">Select a group to start chatting</div>';
        }

        await loadGroups();

    } catch (error) {
        console.error('Failed to leave group:', error);
        alert('Failed to leave group: ' + error.message);
    }
}

// ============================================
// Utility Functions
// ============================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// ============================================
// Export functions for global access
// ============================================

// Make functions available globally for onclick handlers
window.groupChat = {
    removeMember,
    promoteMember,
    closeCreateGroupModal,
    closeManageMembersModal
};

// Export for module usage
export {
    loadGroups,
    selectGroup,
    sendGroupMessage,
    clearGroupSelection,
    closeCreateGroupModal,
    closeManageMembersModal
};
