import { APIClient } from './api.js';
import {
    deriveMasterSeed,
    createNewKeyring,
    encryptKeyring,
    decryptKeyring,
    getCurrentPublicKey,
    setKeyring
} from './crypto.js';

const api = new APIClient();

// DOM elements
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const showRegisterLink = document.getElementById('show-register');
const showLoginLink = document.getElementById('show-login');
const errorMessage = document.getElementById('error-message');
const successMessage = document.getElementById('success-message');
const loginLoading = document.getElementById('login-loading');
const registerLoading = document.getElementById('register-loading');

// Switch between login and register forms
showRegisterLink.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
    clearMessages();
});

showLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    registerForm.style.display = 'none';
    loginForm.style.display = 'block';
    clearMessages();
});

// Handle registration
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages();

    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;
    const passwordConfirm = document.getElementById('register-password-confirm').value;

    // Validate
    if (password !== passwordConfirm) {
        showError('Passwords do not match');
        return;
    }

    if (password.length < 8) {
        showError('Password must be at least 8 characters');
        return;
    }

    if (username.length < 6) {
        showError('Username must be at least 6 characters');
        return;
    }

    try {
        registerLoading.style.display = 'block';
        document.querySelector('#registerForm button[type="submit"]').disabled = true;

        await api.init(); // Ensure API is initialized before making requests

        await api.register(username, password);

        showSuccess('Account created successfully! Please login.');
        registerForm.style.display = 'none';
        loginForm.style.display = 'block';

        // Pre-fill login form
        document.getElementById('login-username').value = username;

    } catch (error) {
        showError(error.message);
    } finally {
        registerLoading.style.display = 'none';
        document.querySelector('#registerForm button[type="submit"]').disabled = false;
    }
});

// Handle login
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages();

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showError('Please enter username and password');
        return;
    }

    try {
        loginLoading.style.display = 'block';
        document.querySelector('#loginForm button[type="submit"]').disabled = true;

        await api.init(); // Ensure API is initialized before making requests
        // Login to backend first
        const loginData = await api.login(username, password);

        // Store basic session info
        sessionStorage.setItem('username', username);
        sessionStorage.setItem('user_id', loginData.user_id);
        sessionStorage.setItem('key_generation_number', loginData.key_generation_number);

        // Initialize keyring (new keyring model)
        let keyring;
        try {
            keyring = await initializeKeyring(password);
        } catch (keyringError) {
            // If keyring fails, fall back to HD key derivation for backward compatibility
            console.warn('Keyring initialization failed, falling back to HD keys:', keyringError);
            keyring = await fallbackToHDKeys(username, password, loginData);
        }

        // Store keyring in memory and session
        setKeyring(keyring);
        sessionStorage.setItem('keyring', JSON.stringify(keyring));

        // Upload current public key to server
        const currentPublicKey = getCurrentPublicKey(keyring);
        await api.updatePublicKey(currentPublicKey);

        // Redirect to chat
        window.location.href = 'chat';

    } catch (error) {
        showError(error.message);
    } finally {
        loginLoading.style.display = 'none';
        document.querySelector('#loginForm button[type="submit"]').disabled = false;
    }
});

/**
 * Initialize keyring - fetch from server or create new one
 * @param {string} password - User's password for encryption/decryption
 * @returns {Promise<object>} - The decrypted keyring
 */
async function initializeKeyring(password) {
    // Fetch keyring from server
    const keyringData = await api.getKeyring();

    if (keyringData.has_keyring) {
        // Existing user: decrypt keyring
        console.log('Decrypting existing keyring...');
        const keyring = await decryptKeyring({
            encryptedKeyring: keyringData.encrypted_keyring,
            nonce: keyringData.nonce,
            salt: keyringData.salt
        }, password);
        console.log('Keyring decrypted successfully');
        return keyring;
    } else {
        // New user: create and upload keyring
        console.log('Creating new keyring...');
        const keyring = await createNewKeyring();

        // Encrypt and upload
        const encrypted = await encryptKeyring(keyring, password);
        await api.uploadKeyring(encrypted.encryptedKeyring, encrypted.nonce, encrypted.salt);
        console.log('New keyring created and uploaded');

        return keyring;
    }
}

/**
 * Fallback to HD key derivation for backward compatibility
 * Creates a keyring from HD-derived keys
 */
async function fallbackToHDKeys(username, password, loginData) {
    const argonParams = {
        memory: 65536,
        iterations: 3,
        parallelism: 4,
    };

    let username2 = username;
    let password2 = password;
    while (username2.length < 16) {
        username2 += "_";
    }
    while (password2.length < 16) {
        password2 += "_";
    }

    const masterSeed = await deriveMasterSeed(password2, username2, argonParams);

    // Store master seed for legacy key derivation
    sessionStorage.setItem('master_seed', arrayToBase64(masterSeed));
    sessionStorage.setItem('argon2_memory', loginData.argon2_memory);
    sessionStorage.setItem('argon2_iterations', loginData.argon2_iterations);
    sessionStorage.setItem('argon2_parallelism', loginData.argon2_parallelism);
    sessionStorage.setItem('use_legacy_hd_keys', 'true');

    // Return a minimal keyring structure for compatibility
    // The actual keys will be derived on-demand using the master seed
    return {
        version: 0, // Version 0 indicates legacy HD mode
        legacyMode: true,
        identityKeys: [] // Keys derived on-demand
    };
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
    successMessage.style.display = 'none';
}

function showSuccess(message) {
    successMessage.textContent = message;
    successMessage.style.display = 'block';
    errorMessage.style.display = 'none';
}

function clearMessages() {
    errorMessage.style.display = 'none';
    successMessage.style.display = 'none';
}

function arrayToBase64(array) {
    let binary = '';
    const bytes = new Uint8Array(array);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Check if already logged in (check for keyring or legacy master_seed)
if (api.token && (sessionStorage.getItem('keyring') || sessionStorage.getItem('master_seed'))) {
    window.location.href = 'chat';
}
