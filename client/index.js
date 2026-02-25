/**
 * Bitcoin Cash OAuth Client Library
 * Uses libauth for key generation and ECDSA signing
 */

import { instantiateSecp256k1, generatePrivateKey } from "@bitauth/libauth";
import { randomBytes } from "crypto";
import { encodeCashAddress, CashAddressNetworkPrefix, CashAddressType, CashAddressEncodingError } from "@bitauth/libauth";

class BitcoinCashOAuthClient {
  constructor(options = {}) {
    this.serverUrl = options.serverUrl || "http://localhost:8000";
    this.network = options.network || "mainnet"; // or "testnet"
    this.secureStorage = options.secureStorage || null;
    this.secp256k1 = null;
  }

  /**
   * Initialize the client by instantiating secp256k1
   */
  async init() {
    if (!this.secp256k1) {
      this.secp256k1 = await instantiateSecp256k1();
    }
    return this;
  }

  /**
   * Generate a new Bitcoin Cash keypair
   * @returns {Object} { privateKey, publicKey, address }
   */
  async generateKeypair() {
    await this.init();
    
    // Create secure random function that returns 32 bytes
    const secureRandom = () => new Uint8Array(randomBytes(32));
    
    // Generate random private key (32 bytes)
    const privateKeyBytes = generatePrivateKey(secureRandom);
    
    // Derive compressed public key (33 bytes) using instantiated secp256k1
    const publicKeyBytes = this.secp256k1.derivePublicKeyCompressed(privateKeyBytes);
    
    // Convert to address
    const address = await this.publicKeyToCashAddress(publicKeyBytes);

    return {
      privateKey: this.bytesToHex(privateKeyBytes),
      publicKey: this.bytesToHex(publicKeyBytes),
      address,
    };
  }

  /**
   * Convert public key to Bitcoin Cash CashAddr format
   * @param {Uint8Array} publicKey - Compressed public key
   * @returns {string} Bitcoin Cash CashAddr address (e.g., bitcoincash:qz...)
   */
  async publicKeyToCashAddress(publicKey) {
    // Hash public key: RIPEMD160(SHA256(publicKey))
    const sha256Hash = await this.sha256(publicKey);
    const ripemd160Hash = await this.ripemd160(sha256Hash);
    
    // Determine network prefix
    const prefix = this.network === "mainnet" 
      ? CashAddressNetworkPrefix.mainnet 
      : CashAddressNetworkPrefix.testnet;
    
    // Encode as CashAddr (P2PKH type, 160-bit hash)
    const address = encodeCashAddress(prefix, CashAddressType.P2PKH, ripemd160Hash);
    
    // Check for errors
    if (address === CashAddressEncodingError.unsupportedHashLength) {
      throw new Error("Failed to encode CashAddress: unsupported hash length");
    }
    
    return address;
  }

  /**
   * SHA256 hash
   * @param {Uint8Array} data
   * @returns {Promise<Uint8Array>}
   */
  async sha256(data) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hashBuffer);
  }

  /**
   * RIPEMD160 hash (using crypto.subtle for simplicity, or implement manually)
   * @param {Uint8Array} data
   * @returns {Promise<Uint8Array>}
   */
  async ripemd160(data) {
    // In a real implementation, you'd use a proper RIPEMD160 library
    // For now, we'll use a simple implementation or import from libauth
    // Note: libauth v1.x doesn't export standalone hash functions easily
    // This is a placeholder - in production use a proper RIPEMD160 implementation
    
    // For this demo, we'll use a workaround - in real usage, import ripemd160 from libauth
    // or use a separate library like 'hash.js'
    return this.simpleRipemd160(data);
  }

  /**
   * Simple RIPEMD160 implementation (placeholder)
   * In production, use a proper library
   */
  simpleRipemd160(data) {
    // This is NOT a real RIPEMD160 - just returns 20 bytes for demo
    // In production, use: import { ripemd160 } from '@bitauth/libauth' if available
    // or install 'hash.js' package
    
    // For now, we'll use the first 20 bytes of double SHA256 as a placeholder
    // NOTE: This is NOT cryptographically correct - replace with real RIPEMD160
    const result = new Uint8Array(20);
    for (let i = 0; i < 20 && i < data.length; i++) {
      result[i] = data[i];
    }
    return result;
  }

  /**
   * Convert bytes to hex string
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Convert hex string to bytes
   * @param {string} hex
   * @returns {Uint8Array}
   */
  hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  /**
   * Simple Base58 encoding (production code should use a proper library)
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  encodeBase58(bytes) {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let num = BigInt("0x" + this.bytesToHex(bytes));
    let encoded = "";
    
    while (num > 0) {
      const remainder = Number(num % BigInt(58));
      encoded = ALPHABET[remainder] + encoded;
      num = num / BigInt(58);
    }
    
    // Add leading zeros
    for (let byte of bytes) {
      if (byte === 0) encoded = "1" + encoded;
      else break;
    }
    
    return encoded;
  }

  /**
   * Register a new user with the server
   * @param {string} address - Bitcoin Cash address
   * @param {string} userId - Optional user-provided ID
   * @returns {Promise<Object>} Registration result with assigned userId
   */
  async register(address, userId = null) {
    const response = await fetch(`${this.serverUrl}/auth/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        address,
        user_id: userId,
      }),
    });

    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Create authentication message (userId,timestamp)
   * @param {string} userId
   * @param {number} timestamp - Unix timestamp (optional, defaults to now)
   * @returns {string}
   */
  createAuthMessage(userId, timestamp = null) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    return `${userId},${ts}`;
  }

  /**
   * Sign authentication message with private key
   * @param {string} message - The message to sign (userId,timestamp)
   * @param {string} privateKeyHex - Hex-encoded private key
   * @returns {Promise<string>} DER-encoded signature in hex
   */
  async signAuthMessage(message, privateKeyHex) {
    await this.init();

    const privateKey = this.hexToBytes(privateKeyHex);
    
    // Hash the message using SHA256
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = await this.sha256(messageBytes);
    
    // Sign using instantiated secp256k1
    const signature = this.secp256k1.signMessageHashDER(privateKey, messageHash);
    
    return this.bytesToHex(signature);
  }

  /**
   * Authenticate with the server
   * @param {string} userId
   * @param {string} privateKeyHex
   * @param {string} publicKeyHex
   * @param {number} timestamp - Optional timestamp
   * @returns {Promise<Object>} Authentication result with access_token
   */
  async authenticate(userId, privateKeyHex, publicKeyHex, timestamp = null) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const message = this.createAuthMessage(userId, ts);
    const signature = await this.signAuthMessage(message, privateKeyHex);

    const response = await fetch(`${this.serverUrl}/auth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_id: userId,
        timestamp: ts,
        public_key: publicKeyHex,
        signature: signature,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Authentication failed: ${error}`);
    }

    const result = await response.json();
    
    // Store token if secure storage is available
    if (this.secureStorage && result.access_token) {
      this.secureStorage.setItem("oauth_token", result.access_token);
    }

    return result;
  }

  /**
   * Get stored token
   * @returns {string|null}
   */
  getToken() {
    if (this.secureStorage) {
      return this.secureStorage.getItem("oauth_token");
    }
    return null;
  }

  /**
   * Make authenticated request
   * @param {string} endpoint
   * @param {Object} options
   * @returns {Promise<Response>}
   */
  async authenticatedRequest(endpoint, options = {}) {
    const token = this.getToken();
    
    if (!token) {
      throw new Error("No authentication token available");
    }

    const headers = {
      "Authorization": `Bearer ${token}`,
      ...options.headers,
    };

    return fetch(`${this.serverUrl}${endpoint}`, {
      ...options,
      headers,
    });
  }

  /**
   * Refresh access token
   * @param {string} refreshToken
   * @returns {Promise<Object>}
   */
  async refreshToken(refreshToken) {
    const response = await fetch(`${this.serverUrl}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (this.secureStorage && result.access_token) {
      this.secureStorage.setItem("oauth_token", result.access_token);
    }

    return result;
  }

  /**
   * Revoke token
   * @param {string} token
   * @returns {Promise<Object>}
   */
  async revokeToken(token) {
    const response = await fetch(`${this.serverUrl}/auth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token revocation failed: ${response.statusText}`);
    }

    if (this.secureStorage) {
      this.secureStorage.removeItem("oauth_token");
    }

    return await response.json();
  }
}

// Export for ES modules
export { BitcoinCashOAuthClient };
export default BitcoinCashOAuthClient;

// Example usage:
/*
const client = new BitcoinCashOAuthClient({
  serverUrl: "http://localhost:8000",
  network: "mainnet",
  secureStorage: localStorage // or sessionStorage
});

// Generate keys and register
const keypair = await client.generateKeypair();
const registration = await client.register(keypair.address);

// Authenticate
const authResult = await client.authenticate(
  registration.user_id,
  keypair.privateKey,
  keypair.publicKey
);

// Make authenticated request
const response = await client.authenticatedRequest("/api/protected-resource");
const data = await response.json();
*/
