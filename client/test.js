/**
 * Test script for Bitcoin Cash OAuth Client
 */

import { BitcoinCashOAuthClient } from "./index.js";

async function testClient() {
  console.log("Testing Bitcoin Cash OAuth Client...\n");

  // Create client instance
  const client = new BitcoinCashOAuthClient({
    serverUrl: "http://localhost:8000",
    network: "mainnet",
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
      },
    },
  });

  try {
    // Test 1: Generate keypair
    console.log("1. Generating keypair...");
    const keypair = await client.generateKeypair();
    console.log("   ✓ Private Key:", keypair.privateKey.substring(0, 20) + "...");
    console.log("   ✓ Public Key:", keypair.publicKey.substring(0, 20) + "...");
    console.log("   ✓ Address:", keypair.address);

    // Test 2: Create and sign message
    console.log("\n2. Creating and signing auth message...");
    const userId = "user_12345";
    const timestamp = Math.floor(Date.now() / 1000);
    const message = client.createAuthMessage(userId, timestamp);
    console.log("   ✓ Message:", message);

    const signature = await client.signAuthMessage(message, keypair.privateKey);
    console.log("   ✓ Signature:", signature.substring(0, 40) + "...");

    // Test 3: Show what would be sent to server
    console.log("\n3. Authentication request payload:");
    const authPayload = {
      user_id: userId,
      timestamp: timestamp,
      public_key: keypair.publicKey,
      signature: signature,
    };
    console.log(JSON.stringify(authPayload, null, 2));

    console.log("\n✅ Client tests completed successfully!");
    console.log("\nNote: To test with a live server, ensure the server is running on http://localhost:8000");

  } catch (error) {
    console.error("\n❌ Test failed:", error.message);
    console.error(error.stack);
  }
}

testClient();
