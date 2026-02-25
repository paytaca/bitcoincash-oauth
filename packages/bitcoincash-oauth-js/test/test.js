/**
 * Test script for Bitcoin Cash OAuth Client
 * 
 * Run with: npm test
 */

import { BitcoinCashOAuthClient } from '../src/index.js';
import { sha256, ripemd160 } from '../src/utils.js';

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
    }
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
    const message = client.createAuthMessage(userId, timestamp);
    console.log('  ✓ Message:', message);
    
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
