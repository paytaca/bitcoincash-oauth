/**
 * Bitcoin Cash OAuth Client
 * TypeScript type definitions
 */

export interface Keypair {
  /** Hex-encoded private key */
  privateKey: string;
  /** Hex-encoded compressed public key */
  publicKey: string;
  /** Bitcoin Cash address */
  address: string;
}

export interface SecureStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface OAuthClientOptions {
  /** OAuth server URL (default: "http://localhost:8000") */
  serverUrl?: string;
  /** Network type - "mainnet" or "testnet" (default: "mainnet") */
  network?: 'mainnet' | 'testnet';
  /** Storage interface for tokens */
  secureStorage?: SecureStorage;
  /** Custom fetch implementation (optional) */
  fetch?: typeof fetch;
}

export interface AuthenticationResult {
  /** JWT access token */
  access_token: string;
  /** Refresh token */
  refresh_token: string;
  /** Token expiration in seconds */
  expires_in: number;
  /** Token type (e.g., "bearer") */
  token_type: string;
}

export interface RegistrationResult {
  /** Assigned user ID */
  user_id: string;
  /** Registration status message */
  message?: string;
}

export class BitcoinCashOAuthClient {
  constructor(options?: OAuthClientOptions);
  
  /** Initialize the client by instantiating secp256k1 */
  init(): Promise<BitcoinCashOAuthClient>;
  
  /** Generate a new Bitcoin Cash keypair */
  generateKeypair(): Promise<Keypair>;
  
  /** Convert public key to Bitcoin Cash CashAddr format */
  publicKeyToCashAddress(publicKey: Uint8Array): Promise<string>;
  
  /** Register a new user with the server */
  register(address: string, userId?: string | null): Promise<RegistrationResult>;
  
  /** Create authentication message (userId,timestamp) */
  createAuthMessage(userId: string, timestamp?: number | null): string;
  
  /** Sign authentication message with private key */
  signAuthMessage(message: string, privateKeyHex: string): Promise<string>;
  
  /** Authenticate with the server */
  authenticate(
    userId: string,
    privateKeyHex: string,
    publicKeyHex: string,
    timestamp?: number | null
  ): Promise<AuthenticationResult>;
  
  /** Get stored token */
  getToken(): string | null;
  
  /** Make authenticated request */
  authenticatedRequest(endpoint: string, options?: RequestInit): Promise<Response>;
  
  /** Refresh access token */
  refreshToken(refreshToken: string): Promise<AuthenticationResult>;
  
  /** Revoke token */
  revokeToken(token: string): Promise<{ message: string }>;
  
  // Utility methods
  bytesToHex(bytes: Uint8Array): string;
  hexToBytes(hex: string): Uint8Array;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  ripemd160(data: Uint8Array): Promise<Uint8Array>;
}

export default BitcoinCashOAuthClient;
