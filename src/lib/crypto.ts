/**
 * Secure Client-Side Encryption Utilities
 * Uses AES-GCM 256-bit encryption
 */

export interface EncryptionResult {
  encryptedData: string; // Base64
  encryptedBuffer?: ArrayBuffer; // Raw buffer for efficient storage upload
  iv: string; // Base64
  key: string; // Base64 key to be put in URL fragment
}

/**
 * Encrypts a string or ArrayBuffer using AES-GCM
 */
export async function encryptData(data: ArrayBuffer | string): Promise<EncryptionResult> {
  const encoder = new TextEncoder();
  const rawData = typeof data === 'string' ? encoder.encode(data) : data;

  // Generate a cryptographically strong random key
  const key = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // Export key to raw format to store in URL
  const exportedKey = await window.crypto.subtle.exportKey('raw', key);
  const keyBase64 = arrayBufferToBase64(exportedKey);

  // Generate a random IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    rawData
  );

  return {
    encryptedData: arrayBufferToBase64(encrypted),
    encryptedBuffer: encrypted,
    iv: arrayBufferToBase64(iv),
    key: keyBase64,
  };
}

/**
 * Decrypts data using AES-GCM
 */
export async function decryptData(
  encrypted: ArrayBuffer, 
  ivBase64: string, 
  keyBase64: string
): Promise<ArrayBuffer> {
  const iv = base64ToArrayBuffer(ivBase64);
  const keyRaw = base64ToArrayBuffer(keyBase64);

  // Import the key back
  const key = await window.crypto.subtle.importKey(
    'raw',
    keyRaw,
    { name: 'AES-GCM' },
    true,
    ['decrypt']
  );

  // Decrypt
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  return decrypted;
}

// Helper: TypedArray/ArrayBuffer to Base64
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper: Base64 to ArrayBuffer
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generates a random secure ID for the share
 */
export function generateId(): string {
  return window.crypto.randomUUID();
}
