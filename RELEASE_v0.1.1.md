# Release v0.1.1

**Release Date:** February 26, 2026

## Summary

Patch release to complete the domain parameter implementation in the authentication API. This fixes a critical omission where the `domain` field was documented but not actually implemented in the server-side token validation.

## What's Changed

### 🐛 Bug Fixes

- **Complete domain parameter implementation**: Added missing `domain` field to token request API in all server implementations
  - Django package (`bitcoincash-oauth-django`): Updated `TokenRequestSerializer` and `TokenView` to accept and pass domain parameter
  - FastAPI package (`bitcoincash-oauth-fastapi`): Updated `TokenRequest` model to include domain field
  - Reference server implementation: Updated `TokenRequest` model and validation call
  - All implementations now properly pass domain to `verify_bitcoin_cash_auth()` validator function

### 📚 Documentation Updates

- Enhanced `/auth/token` endpoint documentation across all packages
- Clarified message format: `bitcoincash-oauth|domain|userId|timestamp`
- Documented domain parameter purpose: phishing prevention by binding signatures to specific domains
- Added backward compatibility note: defaults to "oauth" if not provided

## API Changes

### Token Request Endpoint

**Previous (broken):**
```json
{
  "user_id": "user_abc123",
  "timestamp": 1234567890,
  "public_key": "0279BE...",
  "signature": "3045022100...",
  "scopes": ["read", "write"]
}
```

**Current (fixed):**
```json
{
  "user_id": "user_abc123",
  "timestamp": 1234567890,
  "domain": "app.example.com",
  "public_key": "0279BE...",
  "signature": "3045022100...",
  "scopes": ["read", "write"]
}
```

## Affected Packages

- `bitcoincash-oauth-django` v0.1.1
- `bitcoincash-oauth-fastapi` v0.1.1  
- `bitcoincash-oauth-client` v0.1.1 (npm)

## Migration Guide

**No breaking changes** - this is a backward-compatible fix:
- The `domain` parameter is optional and defaults to "oauth"
- Existing clients that don't send the domain field will continue to work
- However, we **strongly recommend** including the domain field for proper phishing protection

## Security Considerations

This fix enables the full security model designed for Bitcoin Cash OAuth:
- **Domain binding**: Signatures are now verified against the claimed domain
- **Phishing protection**: Signatures from `app-a.com` will not work on `app-b.com`
- **Cross-protocol protection**: The `bitcoincash-oauth` prefix prevents signature reuse across different protocols

## Full Changelog

See [CHANGELOG.md](./CHANGELOG.md) for complete version history.

## Contributors

- @joemarct

---

**Note:** This release is immediately available on:
- PyPI: `pip install bitcoincash-oauth-django==0.1.1` or `pip install bitcoincash-oauth-fastapi==0.1.1`
- npm: `npm install bitcoincash-oauth-client@0.1.1`
