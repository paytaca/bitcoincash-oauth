/**
 * Environment utilities for cross-platform crypto operations
 * Handles browser vs Node.js differences
 */

let cryptoModule = null;

/**
 * Get the Node.js crypto module (cached)
 * @returns {Object|null} Crypto module or null if not available
 */
async function getNodeCrypto() {
  if (cryptoModule !== null) {
    return cryptoModule;
  }
  
  try {
    // Dynamic import for ES module compatibility
    const crypto = await import('crypto');
    cryptoModule = crypto.default || crypto;
    return cryptoModule;
  } catch (e) {
    cryptoModule = false;
    return null;
  }
}

/**
 * Check if running in browser environment
 * @returns {boolean}
 */
export function isBrowser() {
  return typeof window !== 'undefined' && typeof window.document !== 'undefined';
}

/**
 * Check if running in Node.js environment
 * @returns {boolean}
 */
export function isNode() {
  return typeof process !== 'undefined' && process.versions && process.versions.node;
}

/**
 * Generate secure random bytes (cross-platform)
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export async function getRandomBytes(length) {
  // Browser environment: use crypto.getRandomValues
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    return crypto.getRandomValues(new Uint8Array(length));
  }
  
  // Node.js environment: use crypto module
  const nodeCrypto = await getNodeCrypto();
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.randomBytes(length));
  }
  
  throw new Error('Unable to generate secure random bytes - no crypto implementation available');
}

/**
 * SHA256 hash (cross-platform)
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function sha256(data) {
  // Browser: use crypto.subtle
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hashBuffer);
  }
  
  // Node.js: use crypto module
  const nodeCrypto = await getNodeCrypto();
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.createHash('sha256').update(data).digest());
  }
  
  throw new Error('SHA256 not available');
}

/**
 * RIPEMD160 hash (cross-platform)
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function ripemd160(data) {
  // Node.js: use crypto module (preferred)
  const nodeCrypto = await getNodeCrypto();
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.createHash('ripemd160').update(data).digest());
  }
  
  throw new Error('RIPEMD160 not available. This is required for Bitcoin Cash address generation.');
}

/**
 * Get fetch implementation for current environment
 * @returns {Function} Fetch implementation
 */
export function getFetch() {
  // Use global fetch if available (browser or Node.js 18+)
  if (typeof fetch !== 'undefined') {
    return fetch;
  }
  
  throw new Error('No fetch implementation available. For Node.js < 18, install node-fetch and pass it as an option.');
}
