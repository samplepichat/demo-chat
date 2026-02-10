// Browser Notifications Module
// Handles notification permissions and displaying notifications for messages and group events

let notificationsEnabled = false;
let lastNotificationTime = 0;
const NOTIFICATION_THROTTLE = 1000; // Minimum ms between notifications

/**
 * Request notification permission from the user
 * @returns {Promise<boolean>} - True if permission granted
 */
export async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        console.log('This browser does not support notifications');
        return false;
    }

    if (Notification.permission === 'granted') {
        notificationsEnabled = true;
        return true;
    }

    if (Notification.permission === 'denied') {
        console.log('Notifications are blocked by the user');
        return false;
    }

    // Request permission
    try {
        const permission = await Notification.requestPermission();
        notificationsEnabled = permission === 'granted';
        return notificationsEnabled;
    } catch (error) {
        console.error('Failed to request notification permission:', error);
        return false;
    }
}

/**
 * Check if notifications are currently enabled
 * @returns {boolean}
 */
export function areNotificationsEnabled() {
    return notificationsEnabled && Notification.permission === 'granted';
}

/**
 * Show a notification
 * @param {string} title - Notification title
 * @param {object} options - Notification options (body, icon, tag, etc.)
 * @returns {Notification|null}
 */
export function showNotification(title, options = {}) {
    if (!areNotificationsEnabled()) {
        return null;
    }

    // Throttle notifications
    const now = Date.now();
    if (now - lastNotificationTime < NOTIFICATION_THROTTLE) {
        return null;
    }
    lastNotificationTime = now;

    // Don't show notification if document is visible and focused
    if (document.visibilityState === 'visible' && document.hasFocus()) {
        return null;
    }

    const defaultOptions = {
        vibrate: [200, 100, 200],
        requireInteraction: false,
        silent: false,
        ...options
    };

    try {
        const notification = new Notification(title, defaultOptions);

        // Auto-close after 5 seconds
        setTimeout(() => {
            notification.close();
        }, 5000);

        // Focus window on click
        notification.onclick = () => {
            window.focus();
            notification.close();
            if (options.onclick) {
                options.onclick();
            }
        };

        return notification;
    } catch (error) {
        console.error('Failed to show notification:', error);
        return null;
    }
}

/**
 * Show notification for a new direct message
 * @param {string} senderUsername - Username of the sender
 * @param {string} messagePreview - Preview of the message (optional, for decrypted preview)
 */
export function notifyNewDirectMessage(senderUsername, messagePreview = null) {
    const body = messagePreview
        ? messagePreview.substring(0, 100) + (messagePreview.length > 100 ? '...' : '')
        : 'You have a new encrypted message';

    showNotification(`New message from ${senderUsername}`, {
        body,
        tag: `dm-${senderUsername}`, // Replaces previous notification from same user
        data: { type: 'direct_message', username: senderUsername }
    });
}

/**
 * Show notification for a new group message
 * @param {string} groupName - Name of the group
 * @param {string} senderUsername - Username of the sender
 * @param {string} messagePreview - Preview of the message (optional)
 */
export function notifyNewGroupMessage(groupName, senderUsername, messagePreview = null) {
    const body = messagePreview
        ? `${senderUsername}: ${messagePreview.substring(0, 80)}${messagePreview.length > 80 ? '...' : ''}`
        : `New message from ${senderUsername}`;

    showNotification(`${groupName}`, {
        body,
        tag: `group-${groupName}`, // Replaces previous notification from same group
        data: { type: 'group_message', groupName }
    });
}

/**
 * Show notification when added to a group
 * @param {string} groupName - Name of the group
 * @param {string} addedBy - Username of who added you (optional)
 */
export function notifyAddedToGroup(groupName, addedBy = null) {
    const body = addedBy
        ? `${addedBy} added you to this group`
        : 'You have been added to a new group';

    showNotification(`Added to ${groupName}`, {
        body,
        tag: `group-added-${groupName}`,
        data: { type: 'added_to_group', groupName }
    });
}

/**
 * Show notification when removed from a group
 * @param {string} groupName - Name of the group
 */
export function notifyRemovedFromGroup(groupName) {
    showNotification(`Removed from ${groupName}`, {
        body: 'You have been removed from this group',
        tag: `group-removed-${groupName}`,
        data: { type: 'removed_from_group', groupName }
    });
}

/**
 * Show notification for group key rotation
 * @param {string} groupName - Name of the group
 */
export function notifyGroupKeyRotated(groupName) {
    showNotification(`${groupName} - Security Update`, {
        body: 'Group encryption key has been rotated',
        tag: `group-key-${groupName}`,
        data: { type: 'key_rotated', groupName }
    });
}

/**
 * Register service worker for background notifications
 * @returns {Promise<ServiceWorkerRegistration|null>}
 */
export async function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) {
        console.log('Service workers not supported');
        return null;
    }

    try {
        const registration = await navigator.serviceWorker.register('sw.js');
        console.log('Service worker registered:', registration.scope);
        return registration;
    } catch (error) {
        console.error('Service worker registration failed:', error);
        return null;
    }
}

/**
 * Initialize notifications system
 * Call this on app startup
 */
export async function initNotifications() {
    // Register service worker
    await registerServiceWorker();

    // Check current permission status
    if ('Notification' in window) {
        notificationsEnabled = Notification.permission === 'granted';
    }

    return notificationsEnabled;
}
