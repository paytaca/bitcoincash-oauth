/**
 * Bitcoin Cash OAuth Client Library
 * Universal client that works in both browser and Node.js environments
 * 
 * Uses libauth for key generation and ECDSA signing
 */

import { 
  instantiateSecp256k1, 
  generatePrivateKey,
  encodeCashAddress, 
  CashAddressNetworkPrefix, 
  CashAddressType 
} from "@bitauth/libauth";
import { 
  getFetch, 
  getRandomBytes, 
  sha256, 
  ripemd160 
} from "./utils.js";

/**
 * @typedef {Object} Keypair
 * @property {string} privateKey - Hex-encoded private key
 * @property {string} publicKey - Hex-encoded compressed public key
 * @property {string} address - Bitcoin Cash address
 */

/**
 * @typedef {Object} OAuthClientOptions
 * @property {string} [serverUrl="http://localhost:8000"] - OAuth server URL
 * @property {string} [network="mainnet"] - Network type ("mainnet" or "testnet")
 * @property {SecureStorage} [secureStorage] - Storage interface for tokens
 * @property {Function} [fetch] - Custom fetch implementation (optional)
 */

/**
 * @typedef {Object} SecureStorage
 * @property {function(string): string|null} getItem
 * @property {function(string, string): void} setItem
 * @property {function(string): void} removeItem
 */

/**
 * @typedef {Object} AuthenticationResult
 * @property {string} access_token - JWT access token
 * @property {string} refresh_token - Refresh token
 * @property {number} expires_in - Token expiration in seconds
 * @property {string} token_type - Token type (e.g., "bearer")
 */

/**
 * Bitcoin Cash OAuth Client
 * Universal client library for browser and Node.js
 */
export class BitcoinCashOAuthClient {
  /**
   * Create a new OAuth client instance
   * @param {OAuthClientOptions} options - Configuration options
   */
  constructor(options = {}) {
    this.serverUrl = options.serverUrl || "http://localhost:8000";
    this.network = options.network || "mainnet";
    this.secureStorage = options.secureStorage || null;
    this.fetchImpl = options.fetch || getFetch();
    this.secp256k1 = null;
  }

  /**
   * Initialize the client by instantiating secp256k1
   * @returns {Promise<BitcoinCashOAuthClient>} The initialized client instance
   */
  async init() {
    if (!this.secp256k1) {
      this.secp256k1 = await instantiateSecp256k1();
    }
    return this;
  }

  /**
   * Generate a new Bitcoin Cash keypair
   * @returns {Promise<Keypair>} Keypair object with privateKey, publicKey, and address
   */
  async generateKeypair() {
    await this.init();
    
    // Generate random bytes for private key
    const randomBytes = await getRandomBytes(32);
    
    // libauth's generatePrivateKey expects a function that returns Uint8Array
    // We create a closure that returns our pre-generated random bytes
    const secureRandom = () => randomBytes;
    
    // Generate private key (32 bytes)
    const privateKeyBytes = generatePrivateKey(secureRandom);
    
    // Derive compressed public key (33 bytes)
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
   * @returns {Promise<string>} Bitcoin Cash CashAddr address
   */
  async publicKeyToCashAddress(publicKey) {
    // Hash public key: RIPEMD160(SHA256(publicKey))
    const sha256Hash = await sha256(publicKey);
    const ripemd160Hash = await ripemd160(sha256Hash);
    
    // Determine network prefix
    const prefix = this.network === "mainnet" 
      ? CashAddressNetworkPrefix.mainnet 
      : CashAddressNetworkPrefix.testnet;
    
    // Encode as CashAddr (P2PKH type)
    const address = encodeCashAddress(prefix, CashAddressType.P2PKH, ripemd160Hash);
    
    if (typeof address !== 'string') {
      throw new Error(`Failed to encode CashAddress: ${address}`);
    }
    
    return address;
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
   * Register a new user with the server
   * @param {string} address - Bitcoin Cash address
   * @param {string} [userId] - Optional user-provided ID
   * @returns {Promise<Object>} Registration result with assigned userId
   */
  async register(address, userId = null) {
    const response = await this.fetchImpl(`${this.serverUrl}/auth/register`, {
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
      const error = await response.text();
      throw new Error(`Registration failed: ${response.status} ${response.statusText} - ${error}`);
    }

    return await response.json();
  }

  /**
   * Create authentication message (userId,timestamp)
   * @param {string} userId
   * @param {number} [timestamp] - Unix timestamp (defaults to now)
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
    const messageHash = await sha256(messageBytes);
    
    // Sign using secp256k1
    const signature = this.secp256k1.signMessageHashDER(privateKey, messageHash);
    
    return this.bytesToHex(signature);
  }

  /**
   * Authenticate with the server
   * @param {string} userId
   * @param {string} privateKeyHex
   * @param {string} publicKeyHex
   * @param {number} [timestamp] - Optional timestamp
   * @returns {Promise<AuthenticationResult>} Authentication result with access_token
   */
  async authenticate(userId, privateKeyHex, publicKeyHex, timestamp = null) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const message = this.createAuthMessage(userId, ts);
    const signature = await this.signAuthMessage(message, privateKeyHex);

    const response = await this.fetchImpl(`${this.serverUrl}/auth/token`, {
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
      throw new Error(`Authentication failed: ${response.status} ${response.statusText} - ${error}`);
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
   * @param {string} endpoint - API endpoint (relative to serverUrl)
   * @param {Object} [options] - Fetch options
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

    return this.fetchImpl(`${this.serverUrl}${endpoint}`, {
      ...options,
      headers,
    });
  }

  /**
   * Refresh access token
   * @param {string} refreshToken
   * @returns {Promise<AuthenticationResult>}
   */
  async refreshToken(refreshToken) {
    const response = await this.fetchImpl(`${this.serverUrl}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token refresh failed: ${response.status} ${response.statusText} - ${error}`);
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
    const response = await this.fetchImpl(`${this.serverUrl}/auth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token revocation failed: ${response.status} ${response.statusText} - ${error}`);
    }

    if (this.secureStorage) {
      this.secureStorage.removeItem("oauth_token");
    }

    return await response.json();
  }
}

// Default export
export default BitcoinCashOAuthClient;
