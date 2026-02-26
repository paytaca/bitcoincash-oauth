# Bitcoin Cash OAuth

OAuth2 authentication library using Bitcoin Cash ECDSA signatures for identity verification. This library combines client-side JavaScript (using libauth) for key generation and signing with server-side Python for signature verification and address validation.

## Overview

The authentication flow works as follows:

1. **Registration**: Client generates a Bitcoin Cash address and registers it with the server
2. **Authentication**: Client signs a message containing `protocol|domain|userId|timestamp`, then sends the signature, public key, and other data to the server
3. **Verification**: Server validates the ECDSA signature and converts the public key to a Bitcoin Cash address to verify it matches the registered address
4. **Token Issuance**: Upon successful validation, server issues OAuth2 access and refresh tokens
5. **API Access**: Client uses the access token for authenticated requests

**Message Format:** The signed message uses the format `bitcoincash-oauth|domain|userId|timestamp` where:
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol replay attacks)
- `domain`: The domain/host of the application (prevents phishing across different domains)
- `userId`: The user's unique identifier
- `timestamp`: Unix timestamp for replay attack protection

### CashAddr Format

This library uses the **CashAddr format** (bitcoincash:qz...) for all Bitcoin Cash addresses, which is the modern, preferred format for Bitcoin Cash. This provides:

- **Better user experience**: Distinct from legacy Bitcoin addresses, preventing accidental cross-chain transfers
- **Error detection**: Built-in checksum for typo detection
- **Network identification**: Clear prefix shows if it's mainnet (`bitcoincash:`), testnet (`bchtest:`), or regtest (`bchreg:`)

**Example addresses:**
- Mainnet: `bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5`
- Testnet: `bchtest:qqrxvhnn88gmpczyxry254vcsnl6canmkqvepqak5g`

## Project Structure

```
.
├── client/          # Client-side JavaScript library (libauth)
│   ├── index.js     # Main client library
│   ├── package.json # Client dependencies
│   └── test.js      # Client test script
│
└── server/          # Server-side Python implementation
    ├── main.py           # FastAPI server with OAuth endpoints
    ├── validator.py      # ECDSA and Bitcoin Cash validation
    ├── token_manager.py  # OAuth token management
    ├── requirements.txt  # Server dependencies
    └── test.py           # Server test script
```

## Quick Start

### Server Setup

```bash
cd server
uv pip install -r requirements.txt
python main.py
```

The server will start on `http://localhost:8000`.

### Client Setup

```bash
cd client
npm install
node test.js
```

## API Endpoints

### POST `/auth/register`

Register a new user with a Bitcoin Cash address.

**Request:**
```json
{
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "user_id": "optional_custom_id"
}
```

**Response:**
```json
{
  "user_id": "user_abc123",
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "message": "User registered successfully"
}
```

### POST `/auth/token`

Obtain an OAuth token using Bitcoin Cash signature authentication.

The client must sign a message in format `bitcoincash-oauth|domain|userId|timestamp` where:
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol replay attacks)
- `domain`: The domain/host of the application (prevents phishing across different domains)
- `userId`: The user's unique identifier
- `timestamp`: Unix timestamp for replay attack protection

**Request:**
```json
{
  "user_id": "user_abc123",
  "timestamp": 1234567890,
  "domain": "app.example.com",
  "public_key": "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  "signature": "3045022100...",
  "scopes": ["read", "write"]
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "scopes": ["read", "write"]
}
```

### POST `/auth/refresh`

Refresh an access token.

**Request:**
```json
{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g..."
}
```

### POST `/auth/revoke`

Revoke an access token.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### GET `/auth/me`

Get current user information (requires Bearer token).

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## Client Library Usage

### Initialize Client

```javascript
import { BitcoinCashOAuthClient } from './index.js';

const client = new BitcoinCashOAuthClient({
  serverUrl: "http://localhost:8000",
  network: "mainnet", // or "testnet"
  secureStorage: localStorage // or sessionStorage
});

await client.init();
```

### Generate Keys and Register

```javascript
// Generate new keypair
const keypair = await client.generateKeypair();
console.log("Address:", keypair.address);
console.log("Public Key:", keypair.publicKey);

// Register with server
const registration = await client.register(keypair.address);
console.log("User ID:", registration.user_id);
```

### Authenticate

```javascript
// Authenticate (signs message automatically)
const authResult = await client.authenticate(
  registration.user_id,
  keypair.privateKey,
  keypair.publicKey
);

console.log("Access Token:", authResult.access_token);
console.log("Expires In:", authResult.expires_in);
```

### Make Authenticated Requests

```javascript
// Make request with automatic token header
const response = await client.authenticatedRequest("/api/protected-resource");
const data = await response.json();
```

### Manual Signing (for custom flows)

```javascript
const userId = "user_123";
const timestamp = Math.floor(Date.now() / 1000);
const domain = window.location.host; // Or specify manually

// Create message (format: protocol|domain|userId|timestamp)
const message = client.createAuthMessage(userId, timestamp, domain);
// Returns: "bitcoincash-oauth|app.example.com|user_123|1699999999"

// Sign message
const signature = await client.signAuthMessage(
  message, 
  keypair.privateKey
);
```

## Server-Side Validation

### Using the Validator

```python
from validator import verify_bitcoin_cash_auth

# Validate authentication attempt
is_valid, reason = verify_bitcoin_cash_auth(
    user_id="user_123",
    timestamp=1234567890,
    public_key="0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    signature="3045022100...",
    expected_address="bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
    domain="app.example.com"  # Optional: prevents phishing across domains
)

if is_valid:
    print("Authentication successful")
else:
    print(f"Authentication failed: {reason}")
```
```

### Address Validation

```python
from validator import BitcoinCashValidator

# Validate Bitcoin Cash CashAddr format
is_valid, network = BitcoinCashValidator.validate_cash_address(
    "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5"
)

# Convert public key to CashAddr
address = BitcoinCashValidator.public_key_to_cash_address(
    bytes.fromhex("0279BE..."),
    network="mainnet"
)
```

## Security Considerations

1. **Domain Binding**: Messages include the domain/host to prevent phishing attacks - signatures from `app-a.com` won't work on `app-b.com`
2. **Protocol Prefix**: The `bitcoincash-oauth` prefix prevents signature reuse across different authentication protocols
3. **Timestamp Validation**: The server rejects requests with timestamps older than 5 minutes (configurable) to prevent replay attacks
4. **Signature Verification**: All signatures are verified using secp256k1 curve
5. **Address Verification**: Public keys are converted to addresses and verified against registered addresses
6. **Token Expiration**: Access tokens expire after 1 hour by default
7. **Token Revocation**: Tokens can be revoked and are stored in a revocation list
8. **Storage**: In production, use Redis or a database instead of in-memory storage
9. **HTTPS**: Always use HTTPS in production

## Testing

### Prerequisites

Make sure you have the correct tool versions installed:

```bash
# If using asdf version manager
cd /Users/joemartaganna/Projects/Paytaca/bitcoincash-oauth
asdf install
```

Or manually install:
- Python 3.11.8
- Node.js 20.19.0
- [uv](https://github.com/astral-sh/uv) (Python package installer - much faster than pip)

  Install uv:
  ```bash
  # On macOS/Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh
  
  # On Windows (PowerShell)
  powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```

### Install Dependencies

```bash
# Server dependencies (using uv - much faster than pip)
cd server
uv pip install -r requirements.txt

# Alternative: use pip if you don't have uv
cd server
pip install -r requirements.txt

# Client dependencies
cd client
npm install
```

### Run Server Tests

```bash
cd server
python test.py
```

### Run Client Tests

```bash
cd client
node test.js
```

### Run All Tests

```bash
# Run both server and client tests
cd server && python test.py && cd ../client && node test.js
```

### Integration Testing

1. Start the server:
   ```bash
   cd server
   python main.py
   ```

2. In another terminal, run client tests:
   ```bash
   cd client
   node test.js
   ```

3. The server will be available at `http://localhost:8000`

## Dependencies

### Client

- `@bitauth/libauth`: Bitcoin Cash authentication library

### Server

- `fastapi`: Modern web framework
- `coincurve`: ECDSA signature library
- `base58`: Base58 encoding/decoding
- `python-jose`: JWT token handling

## Configuration

### Server Configuration

Environment variables or modify `token_manager.py`:

```python
# Token TTL settings
access_token_ttl = 3600  # 1 hour
refresh_token_ttl = 2592000  # 30 days
max_tokens_per_user = 5
```

### Client Configuration

```javascript
const client = new BitcoinCashOAuthClient({
  serverUrl: process.env.OAUTH_SERVER_URL,
  network: process.env.NETWORK || "mainnet",
  secureStorage: customStorageImplementation
});
```

## License

MIT

## Contributing

Contributions are welcome! Please ensure:

1. Code follows existing style
2. Tests pass
3. Documentation is updated
4. Security considerations are maintained

## Support

For issues and questions, please use the GitHub issue tracker.
