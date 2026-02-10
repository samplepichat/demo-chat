// API Client for backend communication

let API_BASE = window.location.origin + '/api';

const GITHUB_USER = "martenwallewein";
// 2. Enter the Gist ID
const GIST_ID = "ac029299da0994998f096082f17720da";
// 3. The filename inside the Gist
const FILE_NAME = "status.json";
// ---------------------

async function getApiURL() {
    const rawUrl = `https://gist.githubusercontent.com/${GITHUB_USER}/${GIST_ID}/raw/${FILE_NAME}`;
    const cacheBuster = "?t=" + new Date().getTime();
    try {
        const res = await fetch(rawUrl + cacheBuster);
        if (!res.ok) throw new Error("Gist Unreachable");

        const data = await res.json();
        const newUrl = data.url;

        // LOGIC: Only trigger if the URL is different AND valid
        if (newUrl && !newUrl.includes(window.location.hostname) && newUrl.includes('trycloudflare.com')) {

            // Stop scanning
            API_BASE = newUrl + '/api';
            return; // Stop the interval loop
        }
    } catch (e) {
        console.error(e);
    }
}


export class APIClient {
    constructor() {
        this.token = localStorage.getItem('auth_token');
        // Start fetching the API URL from the Gist
    }

    async init() {
        await getApiURL(); // Start fetching the API URL from the Gist
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('auth_token', token);
    }

    clearToken() {
        this.token = null;
        localStorage.removeItem('auth_token');
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(url, {
            ...options,
            headers,
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }

        return data;
    }

    // Auth endpoints
    async register(username, password) {
        return this.request('/register', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
    }

    async login(username, password) {
        const data = await this.request('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
        this.setToken(data.token);
        return data;
    }

    async logout() {
        try {
            await this.request('/logout', { method: 'POST' });
        } finally {
            this.clearToken();
        }
    }

    async getCurrentUser() {
        return this.request('/me');
    }

    // Key endpoints
    async getCurrentKeyInfo() {
        return this.request('/keys/current');
    }

    async getUserPublicKeyInfo(username) {
        return this.request(`/keys/user/${username}`);
    }

    async rotateKey() {
        return this.request('/keys/rotate', { method: 'POST' });
    }

    async logoutAllSessions() {
        return this.request('/keys/logout-all', { method: 'POST' });
    }

    async updatePublicKey(publicKey) {
        return this.request('/keys/update-public-key', {
            method: 'POST',
            body: JSON.stringify({ public_key: publicKey }),
        });
    }

    // Keyring endpoints
    async getKeyring() {
        return this.request('/keyring');
    }

    async uploadKeyring(encryptedKeyring, nonce, salt) {
        return this.request('/keyring', {
            method: 'POST',
            body: JSON.stringify({
                encrypted_keyring: encryptedKeyring,
                nonce: nonce,
                salt: salt,
            }),
        });
    }

    async rotateKeyring(encryptedKeyring, nonce, salt) {
        return this.request('/keyring/rotate', {
            method: 'POST',
            body: JSON.stringify({
                encrypted_keyring: encryptedKeyring,
                nonce: nonce,
                salt: salt,
            }),
        });
    }

    // Message endpoints
    async sendMessage(recipientUsername, encryptedContent, senderEncryptedContent, keyGenerationUsed, senderKeyGenerationUsed, ephemeralPublicKey, senderEphemeralPublicKey, nonce, senderNonce) {
        return this.request('/messages/send', {
            method: 'POST',
            body: JSON.stringify({
                recipient_username: recipientUsername,
                encrypted_content: encryptedContent,
                sender_encrypted_content: senderEncryptedContent,
                key_generation_used: keyGenerationUsed,
                sender_key_generation_used: senderKeyGenerationUsed,
                ephemeral_public_key: ephemeralPublicKey,
                sender_ephemeral_public_key: senderEphemeralPublicKey,
                nonce: nonce,
                sender_nonce: senderNonce,
            }),
        });
    }

    async getMessages() {
        return this.request('/messages');
    }

    async getConversation(username) {
        return this.request(`/messages/conversation/${username}`);
    }

    // User endpoints
    async getUsers() {
        return this.request('/users');
    }

    // Group endpoints
    async createGroup(name, memberKeys) {
        return this.request('/groups', {
            method: 'POST',
            body: JSON.stringify({
                name,
                members: memberKeys
            }),
        });
    }

    async getGroups() {
        return this.request('/groups');
    }

    async getGroup(groupId) {
        return this.request(`/groups/${groupId}`);
    }

    async getGroupMembers(groupId) {
        return this.request(`/groups/${groupId}/members`);
    }

    async addGroupMember(groupId, memberData) {
        return this.request(`/groups/${groupId}/members`, {
            method: 'POST',
            body: JSON.stringify(memberData),
        });
    }

    async removeGroupMember(groupId, userId) {
        return this.request(`/groups/${groupId}/members/${userId}`, {
            method: 'DELETE',
        });
    }

    async promoteMember(groupId, userId) {
        return this.request(`/groups/${groupId}/members/${userId}/promote`, {
            method: 'POST',
        });
    }

    async leaveGroup(groupId) {
        return this.request(`/groups/${groupId}/leave`, {
            method: 'POST',
        });
    }

    async rotateGroupKey(groupId, newMemberKeys) {
        return this.request(`/groups/${groupId}/rotate-key`, {
            method: 'POST',
            body: JSON.stringify({ new_member_keys: newMemberKeys }),
        });
    }

    async sendGroupMessage(groupId, ciphertext, nonce, keyGeneration) {
        return this.request(`/groups/${groupId}/messages`, {
            method: 'POST',
            body: JSON.stringify({
                ciphertext,
                nonce,
                key_generation: keyGeneration
            }),
        });
    }

    async getGroupMessages(groupId, before = null, limit = 50) {
        let url = `/groups/${groupId}/messages?limit=${limit}`;
        if (before) {
            url += `&before=${encodeURIComponent(before)}`;
        }
        return this.request(url);
    }
}
