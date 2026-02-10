// Group chat cryptographic functions
// Uses Web Crypto API for group key management and message encryption

import { importPublicKey } from './crypto.js';

/**
 * Generate a random 256-bit AES key for group encryption
 * @returns {Promise<CryptoKey>} - AES-GCM key for group messages
 */
export async function generateGroupKey() {
    return await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable so we can encrypt it for members
        ['encrypt', 'decrypt']
    );
}

/**
 * Export group key to raw bytes
 * @param {CryptoKey} groupKey - The AES key
 * @returns {Promise<ArrayBuffer>} - Raw key bytes (32 bytes)
 */
export async function exportGroupKey(groupKey) {
    return await crypto.subtle.exportKey('raw', groupKey);
}

/**
 * Import group key from raw bytes
 * @param {ArrayBuffer} keyBytes - Raw key bytes
 * @returns {Promise<CryptoKey>} - AES-GCM key
 */
export async function importGroupKey(keyBytes) {
    return await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt the group key for a specific member using ECDH
 * @param {CryptoKey} groupKey - The group's AES key
 * @param {CryptoKey|string} memberPublicKey - Member's ECDH public key (CryptoKey or base64 string)
 * @returns {Promise<object>} - { encryptedKey, ephemeralPublicKey, nonce } (all base64)
 */
export async function encryptGroupKeyForMember(groupKey, memberPublicKey) {
    // Import public key if it's a base64 string
    if (typeof memberPublicKey === 'string') {
        memberPublicKey = await importPublicKey(memberPublicKey);
    }

    // Generate ephemeral ECDH key pair for this encryption
    const ephemeralKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: memberPublicKey },
        ephemeralKeyPair.privateKey,
        256
    );

    // Use shared secret as AES key for encrypting the group key
    const aesKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    // Export the group key to raw bytes
    const groupKeyBytes = await exportGroupKey(groupKey);

    // Generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the group key
    const encryptedKey = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        groupKeyBytes
    );

    // Export ephemeral public key
    const ephemeralPublicKeyData = await crypto.subtle.exportKey(
        'raw',
        ephemeralKeyPair.publicKey
    );

    return {
        encryptedKey: arrayBufferToBase64(encryptedKey),
        ephemeralPublicKey: arrayBufferToBase64(ephemeralPublicKeyData),
        nonce: arrayBufferToBase64(nonce)
    };
}

/**
 * Decrypt the group key using user's private key
 * @param {string} encryptedKeyB64 - Base64 encrypted group key
 * @param {string} ephemeralPublicKeyB64 - Base64 ephemeral public key
 * @param {string} nonceB64 - Base64 nonce
 * @param {CryptoKey} privateKey - User's ECDH private key
 * @returns {Promise<CryptoKey>} - Decrypted AES group key
 */
export async function decryptGroupKey(encryptedKeyB64, ephemeralPublicKeyB64, nonceB64, privateKey) {
    // Import ephemeral public key
    const ephemeralPublicKeyData = base64ToArrayBuffer(ephemeralPublicKeyB64);
    const ephemeralPublicKey = await crypto.subtle.importKey(
        'raw',
        ephemeralPublicKeyData,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: ephemeralPublicKey },
        privateKey,
        256
    );

    // Use shared secret as AES key for decrypting
    const aesKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // Decrypt the group key
    const nonce = base64ToArrayBuffer(nonceB64);
    const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);

    const groupKeyBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        encryptedKey
    );

    // Import the decrypted bytes as an AES key
    return await importGroupKey(groupKeyBytes);
}

/**
 * Encrypt a message with the group key
 * @param {string} message - Plain text message
 * @param {CryptoKey} groupKey - Group's AES key
 * @returns {Promise<object>} - { ciphertext, nonce } (both base64)
 */
export async function encryptGroupMessage(message, groupKey) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const messageBytes = new TextEncoder().encode(message);

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        groupKey,
        messageBytes
    );

    return {
        ciphertext: arrayBufferToBase64(ciphertext),
        nonce: arrayBufferToBase64(nonce)
    };
}

/**
 * Decrypt a message with the group key
 * @param {string} ciphertextB64 - Base64 ciphertext
 * @param {string} nonceB64 - Base64 nonce
 * @param {CryptoKey} groupKey - Group's AES key
 * @returns {Promise<string>} - Decrypted message
 */
export async function decryptGroupMessage(ciphertextB64, nonceB64, groupKey) {
    const nonce = base64ToArrayBuffer(nonceB64);
    const ciphertext = base64ToArrayBuffer(ciphertextB64);

    const plaintextBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        groupKey,
        ciphertext
    );

    return new TextDecoder().decode(plaintextBytes);
}

// ============================================
// Utility functions
// ============================================

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
