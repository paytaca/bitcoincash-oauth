# Bitcoin Cash OAuth

OAuth2 authentication library using Bitcoin Cash ECDSA signatures for identity verification.

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/paytaca/bitcoincash-oauth/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Bitcoin Cash OAuth provides decentralized authentication using Bitcoin Cash public/private key pairs instead of passwords. This enables secure, passwordless authentication for web applications.

**Key Features:**
- **Passwordless Authentication**: Uses Bitcoin Cash ECDSA signatures
- **Cross-Platform**: Universal JavaScript client + Python server packages
- **Production Ready**: Database persistence, token blacklisting, automatic refresh
- **Secure**: Domain binding, replay protection, signature verification

## Authentication Flow

1. **Registration**: Client generates a Bitcoin Cash address and registers it
2. **Authentication**: Client signs message `bitcoincash-oauth|domain|userId|timestamp`
3. **Verification**: Server validates ECDSA signature and matches address
4. **Token Issuance**: Server issues OAuth2 access and refresh tokens
5. **API Access**: Client uses Bearer token for authenticated requests

**Message Format:** `bitcoincash-oauth|domain|userId|timestamp`
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol attacks)
- `domain`: Application domain (prevents phishing)
- `userId`: User's unique identifier
- `timestamp`: Unix timestamp (replay protection)

## Packages

This monorepo contains three packages:

### JavaScript Client
**Package**: `bitcoincash-oauth-client`  
**Install**: `npm install bitcoincash-oauth-client`

Universal client library for browser and Node.js using libauth.

- Keypair generation and address derivation
- Automatic token refresh
- Custom error classes
- TypeScript support
- Capacitor/hybrid app support

**📖 [Full Documentation](packages/bitcoincash-oauth-js/README.md)**

### Django Server
**Package**: `bitcoincash-oauth-django`  
**Install**: `pip install bitcoincash-oauth-django`

Django integration with database persistence.

- Django models for users and tokens
- Signature-based registration (prevents wallet squatting)
- Django admin interface
- Management commands
- Webhook signals
- Token blacklist

**📖 [Full Documentation](packages/bitcoincash-oauth-django/README.md)**

### FastAPI Server
**Package**: `bitcoincash-oauth-fastapi`  
**Install**: `pip install bitcoincash-oauth-fastapi`

FastAPI integration with async database support.

- SQLAlchemy async models
- PostgreSQL/MySQL/SQLite support
- Signature-based registration
- Redis cache for token blacklist
- FastAPI dependencies
- Testing utilities

**📖 [Full Documentation](packages/bitcoincash-oauth-fastapi/README.md)**

## Quick Start

### JavaScript Client

```bash
npm install bitcoincash-oauth-client
```

```javascript
import { BitcoinCashOAuthClient } from 'bitcoincash-oauth-client';

const client = new BitcoinCashOAuthClient({
  serverUrl: 'https://api.example.com',
  network: 'mainnet'
});

// Generate keys
const keypair = await client.generateKeypair();

// Register
await client.register(keypair.address);

// Authenticate
const auth = await client.authenticate(
  keypair.address,
  keypair.privateKey,
  keypair.publicKey
);

console.log('Token:', auth.access_token);
```

### Django Server

```bash
pip install bitcoincash-oauth-django
```

```python
# settings.py
INSTALLED_APPS = [
    'bitcoincash_oauth_django',
    ...
]

AUTHENTICATION_BACKENDS = [
    'bitcoincash_oauth_django.authentication.BitcoinCashOAuthBackend',
]

BITCOINCASH_OAUTH = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}

# urls.py
urlpatterns = [
    path('auth/', include('bitcoincash_oauth_django.urls')),
]
```

### FastAPI Server

```bash
pip install bitcoincash-oauth-fastapi
```

```python
from fastapi import FastAPI
from bitcoincash_oauth_fastapi import create_oauth_router, init_oauth

app = FastAPI()

@app.on_event("startup")
async def startup():
    await init_oauth()

app.include_router(create_oauth_router())
```

## API Endpoints

All server packages provide these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user (signature verification optional/configurable) |
| `/auth/token` | POST | Obtain OAuth token via signature |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/revoke` | POST | Revoke access token |
| `/auth/me` | GET | Get current user info |

### Registration

Registration supports optional signature-based verification to prevent wallet address squatting:

**Basic Registration:**
```json
POST /auth/register
{
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "user_id": "optional_custom_id"
}
```

**Signature-Based Registration (when enabled):**
```json
POST /auth/register
{
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "user_id": "optional_custom_id",
  "timestamp": 1234567890,
  "domain": "app.example.com",
  "public_key": "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  "signature": "3045022100..."
}
```

**Signature Message Format:** `bitcoincash-oauth|domain|userId|timestamp|register`

## Security Features

- **Signature-Based Authentication**: ECDSA signatures using secp256k1
- **Signature-Based Registration**: Optional proof-of-ownership to prevent address squatting
- **Domain Binding**: Prevents phishing across different domains
- **Replay Protection**: Timestamp validation (5-minute window)
- **Token Rotation**: Refresh tokens rotate for enhanced security
- **Immediate Revocation**: Cache-based blacklist across all workers
- **CashAddr Format**: Modern Bitcoin Cash address format

## Project Structure

```
.
├── packages/
│   ├── bitcoincash-oauth-js/        # JavaScript client (npm)
│   ├── bitcoincash-oauth-django/    # Django package (PyPI)
│   └── bitcoincash-oauth-fastapi/   # FastAPI package (PyPI)
│
├── CHANGELOG.md                     # Release notes
└── README.md                        # This file
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and migration guides.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/paytaca/bitcoincash-oauth/issues).
