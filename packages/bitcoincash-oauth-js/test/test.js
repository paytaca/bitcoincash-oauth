/**
 * Test script for Bitcoin Cash OAuth Client
 * 
 * Run with: npm test
 */

import { 
  BitcoinCashOAuthClient,
  OAuthError,
  NetworkError,
  AuthenticationError,
  TokenExpiredError,
  UserNotFoundError,
  InvalidTokenError
} from '../src/index.js';
import { sha256, ripemd160, isCapacitor, isHybridApp } from '../src/utils.js';

async function runTests() {
  console.log('🧪 Testing Bitcoin Cash OAuth Client\n');
  
  const client = new BitcoinCashOAuthClient({
    serverUrl: 'http://localhost:8000',
    network: 'mainnet',
    secureStorage: {
      storage: {},
      getItem(key) {
        return this.storage[key] || null;
      },
      setItem(key, value) {
        this.storage[key] = value;
      },
      removeItem(key) {
        delete this.storage[key];
      }
    },
    debug: true
  });

  let passed = 0;
  let failed = 0;

  // Test 1: Initialization
  try {
    console.log('Test 1: Initialize client...');
    await client.init();
    console.log('  ✓ Client initialized successfully');
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 2: Generate keypair
  let keypair;
  try {
    console.log('\nTest 2: Generate keypair...');
    keypair = await client.generateKeypair();
    console.log('  ✓ Private Key:', keypair.privateKey.substring(0, 20) + '...');
    console.log('  ✓ Public Key:', keypair.publicKey.substring(0, 20) + '...');
    console.log('  ✓ Address:', keypair.address);
    
    // Validate address format
    if (keypair.address.startsWith('bitcoincash:') || keypair.address.startsWith('bchtest:')) {
      console.log('  ✓ Address format is valid');
      passed++;
    } else {
      throw new Error('Invalid address format');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 3: Create and sign auth message
  try {
    console.log('\nTest 3: Create and sign auth message...');
    const userId = 'user_12345';
    const timestamp = Math.floor(Date.now() / 1000);
    const domain = 'test.example.com';
    const message = client.createAuthMessage(userId, timestamp, domain);
    console.log('  ✓ Message:', message);
    
    // Verify message format
    const parts = message.split('|');
    if (parts.length === 4 && parts[0] === 'bitcoincash-oauth' && parts[2] === userId) {
      console.log('  ✓ Message format is correct (protocol|domain|userId|timestamp)');
    } else {
      throw new Error('Invalid message format');
    }
    
    const signature = await client.signAuthMessage(message, keypair.privateKey);
    console.log('  ✓ Signature:', signature.substring(0, 40) + '...');
    
    if (signature.length > 0 && /^[0-9a-fA-F]+$/.test(signature)) {
      console.log('  ✓ Signature is valid hex');
      passed++;
    } else {
      throw new Error('Invalid signature format');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 4: Hex encoding/decoding
  try {
    console.log('\nTest 4: Hex encoding/decoding...');
    const original = new Uint8Array([0, 1, 255, 128]);
    const hex = client.bytesToHex(original);
    const decoded = client.hexToBytes(hex);
    
    if (hex === '0001ff80' && 
        decoded.length === original.length &&
        decoded.every((v, i) => v === original[i])) {
      console.log('  ✓ Hex encoding/decoding works correctly');
      passed++;
    } else {
      throw new Error('Hex encoding/decoding mismatch');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 5: Hash functions
  try {
    console.log('\nTest 5: Hash functions...');
    const data = new TextEncoder().encode('test');
    
    const sha256Result = await sha256(data);
    console.log('  ✓ SHA256:', client.bytesToHex(sha256Result).substring(0, 16) + '...');
    
    const ripemd160Result = await ripemd160(sha256Result);
    console.log('  ✓ RIPEMD160:', client.bytesToHex(ripemd160Result).substring(0, 16) + '...');
    
    if (sha256Result.length === 32 && ripemd160Result.length === 20) {
      console.log('  ✓ Hash lengths are correct');
      passed++;
    } else {
      throw new Error('Incorrect hash lengths');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 6: Secure storage
  try {
    console.log('\nTest 6: Secure storage...');
    client.secureStorage.setItem('test_key', 'test_value');
    const value = client.secureStorage.getItem('test_key');
    client.secureStorage.removeItem('test_key');
    const removed = client.secureStorage.getItem('test_key');
    
    if (value === 'test_value' && removed === null) {
      console.log('  ✓ Storage get/set/remove works');
      passed++;
    } else {
      throw new Error('Storage operations failed');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 7: Custom storage keys
  try {
    console.log('\nTest 7: Custom storage keys...');
    const customClient = new BitcoinCashOAuthClient({
      serverUrl: 'http://localhost:8000',
      secureStorage: client.secureStorage,
      tokenKey: 'custom_token_key',
      refreshTokenKey: 'custom_refresh_key'
    });
    
    // Simulate token storage
    customClient.secureStorage.setItem('custom_token_key', 'access_token_123');
    customClient.secureStorage.setItem('custom_refresh_key', 'refresh_token_456');
    
    const accessToken = customClient.getToken();
    const refreshToken = customClient.getRefreshToken();
    
    if (accessToken === 'access_token_123' && refreshToken === 'refresh_token_456') {
      console.log('  ✓ Custom storage keys work correctly');
      passed++;
    } else {
      throw new Error('Custom storage keys failed');
    }
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 8: Error classes
  try {
    console.log('\nTest 8: Error classes...');
    
    const oauthError = new OAuthError('Test error', 'TEST_CODE', 400);
    if (oauthError.code !== 'TEST_CODE' || oauthError.statusCode !== 400) {
      throw new Error('OAuthError properties incorrect');
    }
    
    const networkError = new NetworkError('Network failed');
    if (networkError.code !== 'NETWORK_ERROR') {
      throw new Error('NetworkError code incorrect');
    }
    
    const authError = new AuthenticationError('Auth failed', 401);
    if (authError.statusCode !== 401) {
      throw new Error('AuthenticationError statusCode incorrect');
    }
    
    const tokenExpired = new TokenExpiredError();
    if (tokenExpired.code !== 'TOKEN_EXPIRED' || tokenExpired.statusCode !== 401) {
      throw new Error('TokenExpiredError properties incorrect');
    }
    
    const userNotFound = new UserNotFoundError();
    if (userNotFound.code !== 'USER_NOT_FOUND' || userNotFound.statusCode !== 404) {
      throw new Error('UserNotFoundError properties incorrect');
    }
    
    const invalidToken = new InvalidTokenError();
    if (invalidToken.code !== 'INVALID_TOKEN' || invalidToken.statusCode !== 401) {
      throw new Error('InvalidTokenError properties incorrect');
    }
    
    console.log('  ✓ All error classes work correctly');
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 9: Domain in auth message
  try {
    console.log('\nTest 9: Domain in authentication message...');
    const userId = 'test_user';
    const timestamp = 1234567890;
    
    // Test with domain
    const messageWithDomain = client.createAuthMessage(userId, timestamp, 'example.com');
    if (!messageWithDomain.includes('example.com')) {
      throw new Error('Domain not included in message');
    }
    
    // Test without domain (should use default)
    const messageWithoutDomain = client.createAuthMessage(userId, timestamp);
    if (!messageWithoutDomain.includes('|')) {
      throw new Error('Message format incorrect without domain');
    }
    
    console.log('  ✓ Domain handling works correctly');
    console.log('  ✓ Message with domain:', messageWithDomain);
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 10: Token validation
  try {
    console.log('\nTest 10: Token validation...');
    
    // Should return false when no token stored
    const noToken = await client.isTokenValid();
    if (noToken !== false) {
      throw new Error('Token validation should return false when no token');
    }
    
    // Simulate storing a token
    client.secureStorage.setItem(client.tokenKey, 'test_token');
    const hasToken = await client.isTokenValid();
    if (hasToken !== true) {
      throw new Error('Token validation should return true when token exists');
    }
    
    console.log('  ✓ Token validation works correctly');
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 11: Debug mode
  try {
    console.log('\nTest 11: Debug mode...');
    
    const debugClient = new BitcoinCashOAuthClient({
      debug: true
    });
    
    if (!debugClient.debug) {
      throw new Error('Debug mode should be enabled');
    }
    
    // Test that _log method exists and works
    debugClient._log('Test debug message');
    debugClient._log('Test with data', { key: 'value' });
    
    console.log('  ✓ Debug mode works correctly');
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Test 12: Destroy method
  try {
    console.log('\nTest 12: Destroy method...');
    
    const destroyClient = new BitcoinCashOAuthClient({
      autoRefresh: true
    });
    
    // Set some internal state
    destroyClient.tokenExpiry = Date.now() + 3600000;
    destroyClient._authParams = { userId: 'test' };
    
    // Call destroy
    destroyClient.destroy();
    
    if (destroyClient._authParams !== null) {
      throw new Error('Auth params should be cleared after destroy');
    }
    
    console.log('  ✓ Destroy method works correctly');
    passed++;
  } catch (error) {
    console.log('  ✗ Failed:', error.message);
    failed++;
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed`);
  
  if (failed === 0) {
    console.log('\n✅ All tests passed!');
  } else {
    console.log('\n❌ Some tests failed');
    process.exit(1);
  }
}

runTests().catch(error => {
  console.error('\n💥 Fatal error:', error);
  process.exit(1);
});
