# Bitcoin Cash OAuth Client

Universal JavaScript client library for Bitcoin Cash OAuth authentication. Works in both **browser** and **Node.js** environments using the same API.

## Features

- 🔐 **Bitcoin Cash Authentication** - Uses ECDSA signatures for secure authentication
- 🌐 **Universal** - Works in browser and Node.js without changes
- 📦 **Lightweight** - Minimal dependencies using libauth
- 🎯 **TypeScript** - Full TypeScript support with type definitions
- ⚡ **Modern** - Supports ES modules and CommonJS

## Installation

```bash
npm install bitcoincash-oauth-client
```

## Quick Start

### Browser (ES Modules)

```html
<script type="module">
  import { BitcoinCashOAuthClient } from './node_modules/bitcoincash-oauth-client/dist/index.mjs';
  
  const client = new BitcoinCashOAuthClient({
    serverUrl: 'http://localhost:8000',
    network: 'mainnet',
    secureStorage: localStorage
  });
  
  // Generate keypair
  const keypair = await client.generateKeypair();
  console.log('Address:', keypair.address);
  
  // Register and authenticate
  const registration = await client.register(keypair.address);
  const auth = await client.authenticate(
    registration.user_id,
    keypair.privateKey,
    keypair.publicKey
  );
  
  console.log('Access token:', auth.access_token);
</script>
```

### Node.js

```javascript
import { BitcoinCashOAuthClient } from 'bitcoincash-oauth-client';

const client = new BitcoinCashOAuthClient({
  serverUrl: 'http://localhost:8000',
  network: 'mainnet'
  // secureStorage is optional in Node.js
});

async function main() {
  // Generate keypair
  const keypair = await client.generateKeypair();
  console.log('Address:', keypair.address);
  
  // Register and authenticate
  const registration = await client.register(keypair.address);
  const auth = await client.authenticate(
    registration.user_id,
    keypair.privateKey,
    keypair.publicKey
  );
  
  console.log('Authenticated! Token:', auth.access_token);
  
  // Make authenticated request
  const response = await client.authenticatedRequest('/api/protected-resource');
  const data = await response.json();
  console.log(data);
}

main();
```

### CommonJS (Node.js)

```javascript
const { BitcoinCashOAuthClient } = require('bitcoincash-oauth-client');

const client = new BitcoinCashOAuthClient({
  serverUrl: 'http://localhost:8000',
  network: 'mainnet'
});

// ... same usage as ES module version
```

## API Reference

### Constructor Options

```javascript
const client = new BitcoinCashOAuthClient({
  serverUrl: 'http://localhost:8000',  // OAuth server URL
  network: 'mainnet',                  // 'mainnet' or 'testnet'
  secureStorage: localStorage,         // Optional: storage for tokens
  fetch: customFetch                   // Optional: custom fetch implementation
});
```

### Methods

#### `init()`
Initialize the client (automatically called by other methods).

```javascript
await client.init();
```

#### `generateKeypair()`
Generate a new Bitcoin Cash keypair.

```javascript
const { privateKey, publicKey, address } = await client.generateKeypair();
```

**Returns:**
- `privateKey` (string): Hex-encoded private key
- `publicKey` (string): Hex-encoded compressed public key
- `address` (string): Bitcoin Cash CashAddr address

#### `register(address, userId?)`
Register a new user with the OAuth server.

```javascript
const result = await client.register('bitcoincash:qz...', 'optional-user-id');
console.log(result.user_id);
```

#### `authenticate(userId, privateKey, publicKey, timestamp?, domain?)`
Authenticate with the server using ECDSA signature.

```javascript
const auth = await client.authenticate(
  userId,
  privateKeyHex,
  publicKeyHex,
  null,  // Optional: custom timestamp
  'app.example.com'  // Optional: domain for message binding (defaults to window.location.host)
);

console.log(auth.access_token);
console.log(auth.refresh_token);
console.log(auth.expires_in);
```

**Message Format:** The signed message uses the format `bitcoincash-oauth|domain|userId|timestamp`:
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol replay)
- `domain`: Domain/host binding (prevents phishing, defaults to current host)
- `userId`: User's unique identifier
- `timestamp`: Unix timestamp for replay protection

#### `authenticatedRequest(endpoint, options?)`
Make an authenticated HTTP request.

```javascript
const response = await client.authenticatedRequest('/api/user/profile', {
  method: 'GET'
});
const data = await response.json();
```

#### `refreshToken(refreshToken)`
Refresh an expired access token.

```javascript
const newAuth = await client.refreshToken(refreshToken);
```

#### `revokeToken(token)`
Revoke a token on the server.

```javascript
await client.revokeToken(token);
```

#### `getToken()`
Get the currently stored token from secure storage.

```javascript
const token = client.getToken();
```

#### `createAuthMessage(userId, timestamp?, domain?)`
Create the authentication message format used for signing.

```javascript
const message = client.createAuthMessage('user_123', 1234567890, 'app.example.com');
// Returns: "bitcoincash-oauth|app.example.com|user_123|1234567890"
```

**Parameters:**
- `userId` (string): The user's unique identifier
- `timestamp` (number, optional): Unix timestamp (defaults to current time)
- `domain` (string, optional): Domain for message binding (defaults to `window.location.host` or 'oauth')

**Returns:** Message string in format `bitcoincash-oauth|domain|userId|timestamp`

#### `signAuthMessage(message, privateKeyHex)`
Sign an authentication message with a private key.

```javascript
const message = client.createAuthMessage('user_123', 1234567890, 'app.example.com');
// Returns: "bitcoincash-oauth|app.example.com|user_123|1234567890"

const signature = await client.signAuthMessage(message, privateKeyHex);
```

## Storage Interface

The `secureStorage` option accepts any object implementing this interface:

```javascript
interface SecureStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
```

### Browser Example (localStorage)

```javascript
const client = new BitcoinCashOAuthClient({
  secureStorage: localStorage
});
```

### Node.js Example (custom)

```javascript
const client = new BitcoinCashOAuthClient({
  secureStorage: {
    storage: new Map(),
    getItem(key) { return this.storage.get(key) || null; },
    setItem(key, value) { this.storage.set(key, value); },
    removeItem(key) { this.storage.delete(key); }
  }
});
```

## Requirements

- **Node.js**: 14.0.0 or higher
- **Browser**: Modern browsers with ES2018+ support
- **Fetch API**: Available natively in Node.js 18+ and all modern browsers

## Build from Source

```bash
cd packages/bitcoincash-oauth-js
npm install
npm run build
```

## License

MIT
