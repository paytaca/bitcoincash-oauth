# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-02-26

### Fixed

- **Complete domain parameter implementation**: Added missing `domain` field to token request API in all server implementations
  - Django package: Updated `TokenRequestSerializer` and `TokenView` to accept and pass domain parameter
  - FastAPI package: Updated `TokenRequest` model to include domain field
  - Server reference implementation: Updated `TokenRequest` model and validation call
  - All implementations now properly pass domain to `verify_bitcoin_cash_auth()` validator
  - Updated all README documentation to show the domain field in API examples

### Changed

- **API Documentation**: Enhanced `/auth/token` endpoint documentation across all packages to clarify:
  - Message format: `bitcoincash-oauth|domain|userId|timestamp`
  - Domain parameter is used for phishing prevention by binding signatures to specific domains
  - Backward compatible: defaults to "oauth" if not provided

## [0.1.0] - 2026-02-26

### First Release

Initial release of Bitcoin Cash OAuth - A decentralized authentication system using Bitcoin Cash ECDSA signatures for identity verification. This release includes server-side Python packages for Django and FastAPI frameworks, plus a universal JavaScript client library.

### Features

#### Core Authentication Protocol
- **ECDSA-based Authentication**: Uses Bitcoin Cash public/private key pairs instead of passwords
- **Message Signing Protocol**: Clients sign messages in format `bitcoincash-oauth|domain|userId|timestamp`
- **Domain Binding**: Signatures include domain to prevent phishing attacks across different sites
- **Replay Protection**: Timestamps prevent replay attacks (5-minute window)
- **CashAddr Format**: Modern Bitcoin Cash address format with built-in error detection

#### Python Server Packages

**bitcoincash-oauth-django**
- Django authentication backend for Bitcoin Cash OAuth
- Django REST Framework integration with custom authentication classes
- Middleware for automatic signature verification
- Database models for storing user-address mappings
- Management commands for user administration
- Support for Django 4.0+ and Django REST Framework 3.14+

**bitcoincash-oauth-fastapi**
- FastAPI dependency injection system for OAuth authentication
- Automatic JWT token generation and validation
- Async/await support for high-performance applications
- Built-in rate limiting and security headers
- Redis integration for token storage (optional)

#### JavaScript Client Library

**bitcoincash-oauth-client**
- Universal library supporting both browser and Node.js environments
- Keypair generation using libauth (pure JavaScript, no native dependencies)
- Automatic message signing and signature formatting
- Token refresh handling with automatic retry
- Secure storage abstraction (works with localStorage, sessionStorage, or custom storage)
- TypeScript definitions included
- Works with all major JavaScript frameworks (React, Vue, Angular, etc.)

### API Endpoints (Server)

- `POST /auth/register` - Register new user with Bitcoin Cash address
- `POST /auth/token` - Obtain OAuth2 access token via signature authentication
- `POST /auth/refresh` - Refresh expired access tokens
- `POST /auth/revoke` - Revoke access tokens
- `GET /auth/me` - Get current user information

### Security Features

- Signature verification using secp256k1 curve (same as Bitcoin Cash)
- Public key to address conversion for verification
- Protocol prefix to prevent cross-protocol signature reuse
- Configurable token expiration (1 hour default for access tokens)
- Token revocation list support
- HTTPS enforcement recommendations

### Dependencies

**Python Server:**
- `coincurve` >= 18.0.0 - ECDSA signature verification
- `cashaddress` >= 1.0.6 - CashAddr format handling
- `PyJWT` >= 2.8.0 - JWT token generation

**JavaScript Client:**
- `@bitauth/libauth` ^1.19.1 - Bitcoin Cash cryptography

### Installation

```bash
# Django
pip install bitcoincash-oauth-django==0.1.0

# FastAPI
pip install bitcoincash-oauth-fastapi==0.1.0

# JavaScript Client
npm install bitcoincash-oauth-client@0.1.0
```

### Documentation

Full documentation and examples available at: https://github.com/paytaca/bitcoincash-oauth

### Migration from Version 1.0.0

**Note:** Version 1.0.0 was incorrectly published and has been yanked from PyPI and deprecated on npm. This 0.1.0 release is the first official release following Semantic Versioning guidelines (initial development starts at 0.1.0).

If you previously installed version 1.0.0:
- PyPI users: Upgrade to 0.1.0 (this is the same codebase with corrected versioning)
- npm users: Update your package.json to use `"bitcoincash-oauth-client": "0.1.0"`

### Affected Packages
- `bitcoincash-oauth-django` - https://pypi.org/project/bitcoincash-oauth-django/
- `bitcoincash-oauth-fastapi` - https://pypi.org/project/bitcoincash-oauth-fastapi/
- `bitcoincash-oauth-client` - https://www.npmjs.com/package/bitcoincash-oauth-client

[0.1.0]: https://github.com/paytaca/bitcoincash-oauth/releases/tag/v0.1.0
