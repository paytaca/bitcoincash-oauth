/**
 * Custom error classes for Bitcoin Cash OAuth Client
 * Provides specific error types for better error handling
 */

/**
 * Base OAuth Error class
 */
export class OAuthError extends Error {
  /**
   * @param {string} message - Error message
   * @param {string} code - Error code
   * @param {number|null} statusCode - HTTP status code (if applicable)
   */
  constructor(message, code, statusCode = null) {
    super(message);
    this.name = 'OAuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Network-related errors (connection issues, timeouts, etc.)
 */
export class NetworkError extends OAuthError {
  /**
   * @param {string} message - Error message
   * @param {Error|null} originalError - Original error that caused this
   */
  constructor(message, originalError = null) {
    super(message, 'NETWORK_ERROR');
    this.name = 'NetworkError';
    this.originalError = originalError;
  }
}

/**
 * Authentication-related errors (invalid credentials, unauthorized access)
 */
export class AuthenticationError extends OAuthError {
  /**
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   * @param {string} code - Error code
   */
  constructor(message, statusCode, code = 'AUTHENTICATION_ERROR') {
    super(message, code, statusCode);
    this.name = 'AuthenticationError';
  }
}

/**
 * Token has expired
 */
export class TokenExpiredError extends AuthenticationError {
  /**
   * @param {string} [message='Token has expired'] - Error message
   */
  constructor(message = 'Token has expired') {
    super(message, 401, 'TOKEN_EXPIRED');
    this.name = 'TokenExpiredError';
  }
}

/**
 * User not found error
 */
export class UserNotFoundError extends AuthenticationError {
  /**
   * @param {string} [message='User not found'] - Error message
   */
  constructor(message = 'User not found') {
    super(message, 404, 'USER_NOT_FOUND');
    this.name = 'UserNotFoundError';
  }
}

/**
 * Invalid token error
 */
export class InvalidTokenError extends AuthenticationError {
  /**
   * @param {string} [message='Invalid token'] - Error message
   */
  constructor(message = 'Invalid token') {
    super(message, 401, 'INVALID_TOKEN');
    this.name = 'InvalidTokenError';
  }
}
