// Cryptographic functions for keyring-based encryption and message encryption
// Uses Web Crypto API and argon2-browser
//
// KEYRING MODEL: Password encrypts a "keyring" containing random keys
// This separates authentication (password) from encryption (random keys)

/**
 * Derives master seed from username and password using Argon2id
 * @param {string} password - User's password
 * @param {string} username - Username (used as salt)
 * @param {object} params - Argon2 parameters from server
 * @returns {Promise<Uint8Array>} - 64-byte master seed
 */
export async function deriveMasterSeed(password, username, params) {
    // Use argon2-browser library (loaded via CDN in HTML)
    const argon2 = window.argon2;
    const result = await argon2.hash({
        pass: password,
        salt: username,
        time: params.iterations || 3,
        mem: params.memory || 65536, // 64MB in KB
        parallelism: params.parallelism || 4,
        hashLen: 64,
        type: argon2.ArgonType.Argon2id,
    });

    return result.hash;
}

/**
 * Derives a specific key generation from the master seed using HKDF
 * @param {Uint8Array} masterSeed - Master seed
 * @param {number} generation - Key generation number
 * @returns {Promise<CryptoKeyPair>} - X25519 key pair
 */
export async function deriveKeyPair(masterSeed, generation) {
    // Use HKDF to derive key material for this generation
    const info = new TextEncoder().encode(`key-gen-${generation}`);

    // Import master seed as key material
    const baseKey = await crypto.subtle.importKey(
        'raw',
        masterSeed,
        { name: 'HKDF' },
        false,
        ['deriveBits']
    );

    // Derive 32 bytes for X25519 private key
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32), // Use zero salt for deterministic derivation
            info: info,
        },
        baseKey,
        256 // 32 bytes
    );

    const privateKeyBytes = new Uint8Array(derivedBits);

    // Generate deterministic ECDH key pair from the derived seed
    const keyPair = await generateECDHKeyPairFromSeed(privateKeyBytes);

    return keyPair;
}

/**
 * Generate ECDH key pair deterministically from seed using noble-curves
 * @param {Uint8Array} seed - 32-byte seed for key generation
 * @returns {Promise<CryptoKeyPair>} - Deterministic ECDH P-256 key pair
 */
async function generateECDHKeyPairFromSeed(seed) {
    // Ensure seed is exactly 32 bytes
    if (seed.length !== 32) {
        throw new Error('Seed must be 32 bytes');
    }

    // Check if noble-curves is loaded
    if (!window.p256) {
        throw new Error('Noble-curves library (p256) not loaded. Please ensure the script is loaded before using crypto functions.');
    }

    // Use noble-curves to generate deterministic key pair
    // The seed becomes the private key scalar
    const privateKeyScalar = window.p256.utils.normPrivateKeyToScalar(seed);
    const publicKeyPoint = window.p256.ProjectivePoint.BASE.multiply(privateKeyScalar);

    // Export keys in formats compatible with Web Crypto API
    // Convert bigint to bytes (32 bytes for P-256)
    const privateKeyBytes = new Uint8Array(32);
    const privHex = privateKeyScalar.toString(16).padStart(64, '0');
    for (let i = 0; i < 32; i++) {
        privateKeyBytes[i] = parseInt(privHex.slice(i * 2, i * 2 + 2), 16);
    }
    const publicKeyBytes = publicKeyPoint.toRawBytes(false); // 65 bytes uncompressed

    // Convert to JWK format for Web Crypto API import
    const privateKeyJwk = {
        kty: 'EC',
        crv: 'P-256',
        d: bytesToBase64Url(privateKeyBytes),
        x: bytesToBase64Url(publicKeyBytes.slice(1, 33)),
        y: bytesToBase64Url(publicKeyBytes.slice(33, 65)),
        ext: true,
        key_ops: ['deriveBits']
    };

    const publicKeyJwk = {
        kty: 'EC',
        crv: 'P-256',
        x: bytesToBase64Url(publicKeyBytes.slice(1, 33)),
        y: bytesToBase64Url(publicKeyBytes.slice(33, 65)),
        ext: true,
        key_ops: []
    };

    // Import into Web Crypto API
    const privateKey = await crypto.subtle.importKey(
        'jwk',
        privateKeyJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );

    const publicKey = await crypto.subtle.importKey(
        'jwk',
        publicKeyJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
    );

    return { privateKey, publicKey };
}

/**
 * Helper function for base64url encoding (needed for JWK format)
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} - Base64url encoded string
 */
function bytesToBase64Url(bytes) {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Derives all key pairs from generation 0 to N
 * @param {Uint8Array} masterSeed - Master seed
 * @param {number} maxGeneration - Maximum generation number
 * @returns {Promise<Array<CryptoKeyPair>>} - Array of key pairs
 */
export async function deriveAllKeyPairs(masterSeed, maxGeneration) {
    const keyPairs = [];

    for (let i = 0; i <= maxGeneration; i++) {
        const keyPair = await deriveKeyPair(masterSeed, i);
        keyPairs.push(keyPair);
    }

    return keyPairs;
}

/**
 * Encrypts a message using hybrid encryption (ECDH + AES-GCM)
 * @param {string} message - Plain text message
 * @param {CryptoKey} recipientPublicKey - Recipient's public key
 * @returns {Promise<object>} - Encrypted data with ephemeral key and nonce
 */
export async function encryptMessage(message, recipientPublicKey) {
    // Generate ephemeral key pair
    const ephemeralKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipientPublicKey },
        ephemeralKeyPair.privateKey,
        256
    );

    // Derive AES key from shared secret using HKDF
    const aesKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    // Generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt message
    const messageBytes = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        messageBytes
    );

    // Export ephemeral public key
    const ephemeralPublicKeyData = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

    return {
        ciphertext: arrayBufferToBase64(ciphertext),
        ephemeralPublicKey: arrayBufferToBase64(ephemeralPublicKeyData),
        nonce: arrayBufferToBase64(nonce),
    };
}

/**
 * Decrypts a message using hybrid decryption
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} ephemeralPublicKeyB64 - Base64 encoded ephemeral public key
 * @param {string} nonceB64 - Base64 encoded nonce
 * @param {CryptoKey} privateKey - Recipient's private key
 * @returns {Promise<string>} - Decrypted message
 */
export async function decryptMessage(ciphertext, ephemeralPublicKeyB64, nonceB64, privateKey) {
    try {
        // Import ephemeral public key
        const ephemeralPublicKeyData = base64ToArrayBuffer(ephemeralPublicKeyB64);
        const ephemeralPublicKey = await crypto.subtle.importKey(
            'raw',
            ephemeralPublicKeyData,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );

        // Derive shared secret
        const sharedSecret = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: ephemeralPublicKey },
            privateKey,
            256
        );

        // Derive AES key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Decrypt
        const nonce = base64ToArrayBuffer(nonceB64);
        const ciphertextBytes = base64ToArrayBuffer(ciphertext);

        const plaintextBytes = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            aesKey,
            ciphertextBytes
        );

        return new TextDecoder().decode(plaintextBytes);
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    }
}

/**
 * Exports a public key to base64 for transmission
 */
export async function exportPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey('raw', publicKey);
    return arrayBufferToBase64(exported);
}

/**
 * Imports a public key from base64
 */
export async function importPublicKey(base64Key) {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
}

// Utility functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ============================================
// KEYRING ENCRYPTION/DECRYPTION
// ============================================

/**
 * Keyring structure stored encrypted on server:
 * {
 *   version: 1,
 *   identityKeys: [
 *     { generation: 0, privateKey: jwk, publicKey: base64, createdAt: timestamp },
 *     { generation: 1, privateKey: jwk, publicKey: base64, createdAt: timestamp },
 *     ...
 *   ]
 * }
 */

// Current keyring held in memory during session
let currentKeyring = null;

/**
 * Derive encryption key from password for keyring encryption
 * Uses HIGHER cost than regular derivation since this only happens on login
 * @param {string} password - User's password
 * @param {Uint8Array} salt - Random salt for key derivation
 * @returns {Promise<Uint8Array>} - 32-byte encryption key
 */
async function deriveKeyringEncryptionKey(password, salt) {
    const argon2 = window.argon2;
    const result = await argon2.hash({
        pass: password,
        salt: salt,
        time: 5,          // Higher iteration count for keyring
        mem: 131072,      // 128 MB memory (more expensive)
        parallelism: 4,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id,
    });
    return result.hash;
}

/**
 * Encrypt the keyring with the user's password
 * @param {object} keyring - The keyring object to encrypt
 * @param {string} password - User's password
 * @returns {Promise<object>} - { encryptedKeyring, nonce, salt }
 */
export async function encryptKeyring(keyring, password) {
    // Generate random salt and nonce
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Derive encryption key from password
    const encryptionKey = await deriveKeyringEncryptionKey(password, salt);

    // Import as AES key
    const aesKey = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    // Encrypt keyring JSON
    const keyringBytes = new TextEncoder().encode(JSON.stringify(keyring));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        keyringBytes
    );

    return {
        encryptedKeyring: arrayBufferToBase64(ciphertext),
        nonce: arrayBufferToBase64(nonce),
        salt: arrayBufferToBase64(salt)
    };
}

/**
 * Decrypt the keyring with the user's password
 * @param {object} encryptedData - { encryptedKeyring, nonce, salt }
 * @param {string} password - User's password
 * @returns {Promise<object>} - Decrypted keyring object
 */
export async function decryptKeyring(encryptedData, password) {
    const { encryptedKeyring, nonce, salt } = encryptedData;

    // Derive encryption key from password
    const saltBytes = new Uint8Array(base64ToArrayBuffer(salt));
    const encryptionKey = await deriveKeyringEncryptionKey(password, saltBytes);

    // Import as AES key
    const aesKey = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // Decrypt keyring
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(base64ToArrayBuffer(nonce)) },
        aesKey,
        new Uint8Array(base64ToArrayBuffer(encryptedKeyring))
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============================================
// RANDOM KEY GENERATION
// ============================================

/**
 * Generate a new random ECDH key pair
 * @returns {Promise<object>} - { privateKey: jwk, publicKey: base64, createdAt: timestamp }
 */
async function generateRandomKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,  // Extractable so we can store in keyring
        ['deriveBits']
    );

    // Export keys for storage
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

    return {
        privateKey: privateKeyJwk,
        publicKey: arrayBufferToBase64(publicKeyRaw),
        createdAt: Date.now()
    };
}

// ============================================
// KEYRING LIFECYCLE
// ============================================

/**
 * Create a new keyring for a new user
 * @returns {Promise<object>} - New keyring with initial key pair
 */
export async function createNewKeyring() {
    const identityKeyPair = await generateRandomKeyPair();

    return {
        version: 1,
        identityKeys: [
            {
                generation: 0,
                ...identityKeyPair
            }
        ]
    };
}

/**
 * Add a new key generation to existing keyring (for key rotation)
 * @param {object} keyring - Current keyring
 * @returns {Promise<object>} - Updated keyring with new key
 */
export async function rotateKeyInKeyring(keyring) {
    const newGeneration = keyring.identityKeys.length;
    const newKeyPair = await generateRandomKeyPair();

    keyring.identityKeys.push({
        generation: newGeneration,
        ...newKeyPair
    });

    return keyring;
}

/**
 * Get private key CryptoKey for a specific generation
 * @param {object} keyring - The keyring
 * @param {number} generation - Key generation number
 * @returns {Promise<CryptoKey>} - Private key for ECDH
 */
export async function getPrivateKeyForGeneration(keyring, generation) {
    const keyData = keyring.identityKeys.find(k => k.generation === generation);
    if (!keyData) {
        throw new Error(`No key found for generation ${generation}`);
    }

    // Import JWK as CryptoKey
    return await crypto.subtle.importKey(
        'jwk',
        keyData.privateKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits']
    );
}

/**
 * Get current (latest) public key from keyring as base64
 * @param {object} keyring - The keyring
 * @returns {string} - Base64-encoded public key
 */
export function getCurrentPublicKey(keyring) {
    const latestKey = keyring.identityKeys[keyring.identityKeys.length - 1];
    return latestKey.publicKey;
}

/**
 * Get current keyring from memory
 * @returns {object|null} - Current keyring or null if not loaded
 */
export function getKeyring() {
    return currentKeyring;
}

/**
 * Set current keyring in memory
 * @param {object} keyring - Keyring to store
 */
export function setKeyring(keyring) {
    currentKeyring = keyring;
}

/**
 * Clear keyring from memory (on logout)
 */
export function clearKeyring() {
    currentKeyring = null;
}

// ============================================
// MESSAGE ENCRYPTION WITH KEYRING
// ============================================

/**
 * Encrypt a message using keyring-based keys
 * @param {string} message - Plain text message
 * @param {CryptoKey} recipientPublicKey - Recipient's public key
 * @param {object} keyring - Sender's keyring (for sender copy)
 * @returns {Promise<object>} - Encrypted data for both recipient and sender
 */
export async function encryptMessageWithKeyring(message, recipientPublicKey, keyring) {
    // Encrypt for recipient (same as before)
    const recipientEncrypted = await encryptMessage(message, recipientPublicKey);

    // Get sender's current public key for sender copy
    const senderGeneration = keyring.identityKeys.length - 1;
    const senderPublicKeyData = keyring.identityKeys[senderGeneration].publicKey;
    const senderPublicKey = await importPublicKey(senderPublicKeyData);

    // Encrypt for sender
    const senderEncrypted = await encryptMessage(message, senderPublicKey);

    return {
        // For recipient
        encrypted_content: recipientEncrypted.ciphertext,
        ephemeral_public_key: recipientEncrypted.ephemeralPublicKey,
        nonce: recipientEncrypted.nonce,
        // For sender
        sender_encrypted_content: senderEncrypted.ciphertext,
        sender_ephemeral_public_key: senderEncrypted.ephemeralPublicKey,
        sender_nonce: senderEncrypted.nonce,
        sender_key_generation_used: senderGeneration
    };
}

/**
 * Decrypt a message using keyring-based keys
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} ephemeralPublicKeyB64 - Base64 encoded ephemeral public key
 * @param {string} nonceB64 - Base64 encoded nonce
 * @param {number} keyGeneration - Which key generation was used
 * @param {object} keyring - User's keyring
 * @returns {Promise<string>} - Decrypted message
 */
export async function decryptMessageWithKeyring(ciphertext, ephemeralPublicKeyB64, nonceB64, keyGeneration, keyring) {
    const privateKey = await getPrivateKeyForGeneration(keyring, keyGeneration);
    return await decryptMessage(ciphertext, ephemeralPublicKeyB64, nonceB64, privateKey);
}
