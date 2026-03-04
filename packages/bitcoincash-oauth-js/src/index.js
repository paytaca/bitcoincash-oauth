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
  ripemd160,
  isCapacitor
} from "./utils.js";
import {
  OAuthError,
  NetworkError,
  AuthenticationError,
  TokenExpiredError,
  UserNotFoundError,
  InvalidTokenError
} from "./errors.js";

// Re-export error classes for users
export {
  OAuthError,
  NetworkError,
  AuthenticationError,
  TokenExpiredError,
  UserNotFoundError,
  InvalidTokenError
};

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
 * @property {string} [tokenKey="oauth_token"] - Key for storing access token
 * @property {string} [refreshTokenKey="oauth_refresh_token"] - Key for storing refresh token
 * @property {boolean} [autoRefresh=true] - Enable automatic token refresh
 * @property {number} [refreshThreshold=300] - Seconds before expiry to trigger refresh (default: 5 minutes)
 * @property {boolean} [debug=false] - Enable debug logging
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
 * @property {string[]} [scopes] - Granted scopes
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
    this.fetchImpl = options.fetch || getFetch(options.fetch);
    this.secp256k1 = null;
    
    // Token storage keys
    this.tokenKey = options.tokenKey || "oauth_token";
    this.refreshTokenKey = options.refreshTokenKey || "oauth_refresh_token";
    
    // Auto-refresh settings
    this.autoRefresh = options.autoRefresh !== false; // default true
    this.refreshThreshold = options.refreshThreshold || 300; // 5 minutes before expiry
    this.tokenExpiry = null;
    this.refreshPromise = null;
    this.refreshTimer = null;
    
    // Debug mode
    this.debug = options.debug || false;
    
    // Store auth params for refresh
    this._authParams = null;
  }

  /**
   * Log debug messages
   * @private
   * @param {string} message - Message to log
   * @param {*} [data] - Optional data to log
   */
  _log(message, data = null) {
    if (this.debug) {
      if (data !== null) {
        console.log(`[bitcoincash-oauth-client] ${message}`, data);
      } else {
        console.log(`[bitcoincash-oauth-client] ${message}`);
      }
    }
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

    this._log('Generated new keypair', { address });

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
   * @throws {NetworkError} If network request fails
   * @throws {AuthenticationError} If registration fails
   */
  async register(address, userId = null) {
    try {
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
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 404) {
          throw new UserNotFoundError(errorData.detail || 'User not found');
        }
        
        throw new AuthenticationError(
          errorData.detail || `Registration failed: ${response.statusText}`,
          response.status
        );
      }

      this._log('User registered successfully', { address, userId });
      return await response.json();
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw new NetworkError(`Network error during registration: ${error.message}`, error);
    }
  }

  /**
   * Create authentication message (protocol|domain|userId|timestamp)
   * @param {string} userId
   * @param {number} [timestamp] - Unix timestamp (defaults to now)
   * @param {string} [domain] - Domain/host (defaults to window.location.host or 'oauth')
   * @returns {string}
   */
  createAuthMessage(userId, timestamp = null, domain = null) {
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const host = domain || (typeof window !== 'undefined' && window?.location?.host) || 'oauth';
    return `bitcoincash-oauth|${host}|${userId}|${ts}`;
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
   * @param {string} [domain] - Optional domain for message binding
   * @returns {Promise<AuthenticationResult>} Authentication result with access_token
   * @throws {NetworkError} If network request fails
   * @throws {AuthenticationError} If authentication fails
   */
  async authenticate(userId, privateKeyHex, publicKeyHex, timestamp = null, domain = null) {
    this._log('Starting authentication', { userId, domain });
    
    const ts = timestamp || Math.floor(Date.now() / 1000);
    const message = this.createAuthMessage(userId, ts, domain);
    
    this._log('Authentication message created', message);
    
    const signature = await this.signAuthMessage(message, privateKeyHex);
    
    this._log('Message signed successfully');

    try {
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
          domain: domain || this._getDefaultDomain(), // Include domain in payload
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 401) {
          throw new TokenExpiredError(errorData.detail || 'Authentication failed: invalid credentials');
        }
        if (response.status === 404) {
          throw new UserNotFoundError(errorData.detail || 'User not found');
        }
        
        throw new AuthenticationError(
          errorData.detail || `Authentication failed: ${response.statusText}`,
          response.status
        );
      }

      const result = await response.json();
      
      this._log('Authentication successful', { 
        expires_in: result.expires_in,
        token_type: result.token_type 
      });
      
      // Store tokens if secure storage is available
      if (this.secureStorage) {
        if (result.access_token) {
          this.secureStorage.setItem(this.tokenKey, result.access_token);
        }
        if (result.refresh_token) {
          this.secureStorage.setItem(this.refreshTokenKey, result.refresh_token);
        }
      }

      // Track token expiry and schedule refresh
      if (result.expires_in) {
        this.tokenExpiry = Date.now() + (result.expires_in * 1000);
        
        // Store auth params for refresh
        this._authParams = { userId, privateKeyHex, publicKeyHex, domain };
        
        if (this.autoRefresh) {
          this._scheduleRefresh();
        }
      }

      return result;
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw new NetworkError(`Network error during authentication: ${error.message}`, error);
    }
  }

  /**
   * Get default domain for authentication
   * @private
   * @returns {string}
   */
  _getDefaultDomain() {
    if (typeof window !== 'undefined' && window?.location?.host) {
      return window.location.host;
    }
    return 'oauth';
  }

  /**
   * Schedule automatic token refresh
   * @private
   */
  _scheduleRefresh() {
    // Clear any existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    const refreshTime = this.tokenExpiry - (this.refreshThreshold * 1000) - Date.now();
    
    if (refreshTime > 0) {
      this._log(`Scheduling token refresh in ${Math.floor(refreshTime / 1000)} seconds`);
      
      this.refreshTimer = setTimeout(() => {
        this._performRefresh();
      }, refreshTime);
    } else {
      this._log('Token expires too soon, refreshing immediately');
      this._performRefresh();
    }
  }

  /**
   * Perform token refresh
   * @private
   */
  async _performRefresh() {
    if (!this._authParams) {
      this._log('No auth params available for refresh');
      return;
    }

    const { userId, privateKeyHex, publicKeyHex, domain } = this._authParams;
    
    try {
      await this.refreshAccessToken(userId, privateKeyHex, publicKeyHex, domain);
      this._log('Token refreshed automatically');
    } catch (error) {
      this._log('Automatic token refresh failed', error.message);
      // Clear stored tokens on refresh failure
      if (this.secureStorage) {
        this.secureStorage.removeItem(this.tokenKey);
        this.secureStorage.removeItem(this.refreshTokenKey);
      }
    }
  }

  /**
   * Refresh access token with automatic retry on expiration
   * @param {string} userId
   * @param {string} privateKeyHex
   * @param {string} publicKeyHex
   * @param {string} [domain]
   * @returns {Promise<AuthenticationResult>}
   * @throws {AuthenticationError} If refresh fails
   */
  async refreshAccessToken(userId, privateKeyHex, publicKeyHex, domain = null) {
    // Prevent concurrent refresh attempts
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this._doRefresh(userId, privateKeyHex, publicKeyHex, domain);
    
    try {
      const result = await this.refreshPromise;
      return result;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Internal refresh implementation
   * @private
   */
  async _doRefresh(userId, privateKeyHex, publicKeyHex, domain) {
    this._log('Refreshing access token');
    
    // Use refresh token if available, otherwise re-authenticate
    const refreshToken = this.getRefreshToken();
    
    if (refreshToken) {
      try {
        return await this.refreshToken(refreshToken);
      } catch (error) {
        this._log('Refresh token failed, falling back to re-authentication');
      }
    }
    
    // Fall back to full re-authentication
    return await this.authenticate(userId, privateKeyHex, publicKeyHex, null, domain);
  }

  /**
   * Get stored token
   * @returns {string|null}
   */
  getToken() {
    if (this.secureStorage) {
      return this.secureStorage.getItem(this.tokenKey);
    }
    return null;
  }

  /**
   * Get stored refresh token
   * @returns {string|null}
   */
  getRefreshToken() {
    if (this.secureStorage) {
      return this.secureStorage.getItem(this.refreshTokenKey);
    }
    return null;
  }

  /**
   * Validate if the current token is still valid
   * @param {boolean} [serverCheck=false] - If true, validates with the server; if false, only checks local expiry
   * @returns {Promise<boolean>}
   */
  async isTokenValid(serverCheck = false) {
    const token = this.getToken();
    
    if (!token) {
      this._log('Token validation: no token stored');
      return false;
    }

    // Local expiry check
    if (this.tokenExpiry && Date.now() >= this.tokenExpiry) {
      this._log('Token validation: token expired locally');
      return false;
    }

    // Server validation (optional)
    if (serverCheck) {
      try {
        this._log('Token validation: checking with server');
        const response = await this.fetchImpl(`${this.serverUrl}/auth/verify`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
          }
        });
        
        const isValid = response.ok;
        this._log('Token validation: server check result', isValid);
        return isValid;
      } catch (error) {
        this._log('Token validation: server check failed', error.message);
        return false;
      }
    }

    return true;
  }

  /**
   * Make authenticated request with automatic retry on token expiration
   * @param {string} endpoint - API endpoint (relative to serverUrl)
   * @param {Object} [options] - Fetch options
   * @param {Object} [authParams] - Parameters to re-authenticate if needed
   * @param {string} authParams.userId - User ID
   * @param {string} authParams.privateKeyHex - Private key in hex
   * @param {string} authParams.publicKeyHex - Public key in hex
   * @param {string} [authParams.domain] - Domain for authentication
   * @returns {Promise<Response>}
   * @throws {AuthenticationError} If no token available and no auth params provided
   */
  async authenticatedRequest(endpoint, options = {}, authParams = null) {
    const makeRequest = async () => {
      const token = this.getToken();
      if (!token) {
        throw new AuthenticationError('No authentication token available', 401, 'NO_TOKEN');
      }

      const headers = {
        "Authorization": `Bearer ${token}`,
        ...options.headers,
      };

      return this.fetchImpl(`${this.serverUrl}${endpoint}`, {
        ...options,
        headers,
      });
    };

    let response = await makeRequest();

    // If token expired and auth params provided, re-authenticate and retry
    if (response.status === 401 && authParams) {
      this._log('Token expired, re-authenticating...');
      
      await this.authenticate(
        authParams.userId,
        authParams.privateKeyHex,
        authParams.publicKeyHex,
        null,
        authParams.domain
      );

      // Retry the request with new token
      response = await makeRequest();
    }

    return response;
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken
   * @returns {Promise<AuthenticationResult>}
   * @throws {NetworkError} If network request fails
   * @throws {AuthenticationError} If refresh fails
   */
  async refreshToken(refreshToken) {
    try {
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
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 401) {
          throw new InvalidTokenError(errorData.detail || 'Invalid or expired refresh token');
        }
        
        throw new AuthenticationError(
          errorData.detail || `Token refresh failed: ${response.statusText}`,
          response.status
        );
      }

      const result = await response.json();
      
      this._log('Token refreshed successfully');
      
      // Update stored tokens
      if (this.secureStorage) {
        if (result.access_token) {
          this.secureStorage.setItem(this.tokenKey, result.access_token);
        }
        if (result.refresh_token) {
          this.secureStorage.setItem(this.refreshTokenKey, result.refresh_token);
        }
      }

      // Update expiry and reschedule refresh
      if (result.expires_in) {
        this.tokenExpiry = Date.now() + (result.expires_in * 1000);
        
        if (this.autoRefresh) {
          this._scheduleRefresh();
        }
      }

      return result;
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw new NetworkError(`Network error during token refresh: ${error.message}`, error);
    }
  }

  /**
   * Revoke token
   * @param {string} token
   * @returns {Promise<Object>}
   * @throws {NetworkError} If network request fails
   */
  async revokeToken(token) {
    try {
      // Clear any pending refresh
      if (this.refreshTimer) {
        clearTimeout(this.refreshTimer);
        this.refreshTimer = null;
      }
      
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
        const errorData = await response.json().catch(() => ({}));
        throw new AuthenticationError(
          errorData.detail || `Token revocation failed: ${response.statusText}`,
          response.status
        );
      }

      this._log('Token revoked successfully');

      // Clear stored tokens
      if (this.secureStorage) {
        this.secureStorage.removeItem(this.tokenKey);
        this.secureStorage.removeItem(this.refreshTokenKey);
      }

      this.tokenExpiry = null;
      this._authParams = null;

      return await response.json();
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw new NetworkError(`Network error during token revocation: ${error.message}`, error);
    }
  }

  /**
   * Clean up resources (clear timers, etc.)
   * Call this when the client is no longer needed
   */
  destroy() {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this._authParams = null;
    this._log('Client destroyed');
  }
}

// Default export
export default BitcoinCashOAuthClient;
