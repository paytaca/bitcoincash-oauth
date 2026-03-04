# Bitcoin Cash OAuth - FastAPI

Bitcoin Cash OAuth authentication integration for FastAPI applications.

## Installation

```bash
pip install bitcoincash-oauth-fastapi
```

## Quick Start

```python
from fastapi import FastAPI
from bitcoincash_oauth_fastapi import BitcoinCashOAuth

app = FastAPI()

# Initialize OAuth
oauth = BitcoinCashOAuth(
    router_prefix="/auth",
    token_ttl=3600,  # 1 hour
    refresh_token_ttl=2592000,  # 30 days
    max_tokens_per_user=5
)

# Include the OAuth router
app.include_router(oauth.router)

# Protect your routes
@app.get("/api/protected")
async def protected_endpoint(token_data=oauth.get_user_dependency()):
    return {
        "message": "This is protected",
        "user_id": token_data.user_id,
        "scopes": token_data.scopes
    }
```

## API Endpoints

The following endpoints are automatically added:

### POST `/auth/register`

Register a new user with a Bitcoin Cash address. When `REQUIRE_SIGNATURE_FOR_REGISTRATION` is enabled, proof of wallet ownership is required.

**Request (without signature verification):**
```json
{
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "user_id": "optional_custom_id"
}
```

**Request (with signature verification):**
```json
{
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "user_id": "optional_custom_id",
  "timestamp": 1234567890,
  "domain": "app.example.com",
  "public_key": "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  "signature": "3045022100..."
}
```

**Message Format:** `bitcoincash-oauth|domain|userId|timestamp|register`
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol replay)
- `domain`: Domain/host of the application (prevents phishing)
- `userId`: User's unique identifier
- `timestamp`: Unix timestamp for replay protection
- `register`: Action identifier

**Response:**
```json
{
  "user_id": "user_abc123",
  "address": "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
  "message": "User registered successfully",
  "signature_required": false
}
```

### POST `/auth/token`

Obtain an OAuth token using Bitcoin Cash signature. The client must sign the message in the format `bitcoincash-oauth|domain|userId|timestamp`.

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

**Message Format:** `bitcoincash-oauth|domain|userId|timestamp`
- `bitcoincash-oauth`: Protocol identifier (prevents cross-protocol replay)
- `domain`: Domain/host of the application (prevents phishing)
- `userId`: User's unique identifier  
- `timestamp`: Unix timestamp for replay protection

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

## Advanced Usage

### Custom Token Manager

```python
from bitcoincash_oauth_fastapi import TokenManager, token_manager

# Configure the singleton token manager
token_manager.access_token_ttl = 7200  # 2 hours
token_manager.max_tokens_per_user = 10

# Or create your own instance
custom_manager = TokenManager(
    access_token_ttl=7200,
    refresh_token_ttl=604800,  # 7 days
    max_tokens_per_user=10
)
```

### Using the Validator Directly

```python
from bitcoincash_oauth_fastapi import BitcoinCashValidator, verify_bitcoin_cash_auth

# Validate a CashAddr
is_valid, network = BitcoinCashValidator.validate_cash_address(
    "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5"
)

# Verify authentication with domain binding
is_valid, reason = verify_bitcoin_cash_auth(
    user_id="user_123",
    timestamp=1234567890,
    public_key="0279BE...",
    signature="3045...",
    expected_address="bitcoincash:qz7f...",
    domain="app.example.com"  # Optional: prevents phishing across domains
)
```

### Alternative: Simple Router Function

```python
from fastapi import FastAPI
from bitcoincash_oauth_fastapi import create_oauth_router

app = FastAPI()

# Just add the router with default settings
app.include_router(create_oauth_router(), prefix="/auth")
```

## Configuration

All settings can be configured via environment variables with the prefix `BITCOINCASH_OAUTH_`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `USER_MODEL` | `None` | Custom user model path (e.g., `myapp.models.MyBitcoinCashUser`) |
| `TOKEN_MODEL` | `None` | Custom token model path (e.g., `myapp.models.MyOAuthToken`) |

### Custom Models (Avoiding Conflicts)

If your project already has models named `BitcoinCashUser` or `OAuthToken`, you can use custom models:

```python
# main.py
from bitcoincash_oauth_fastapi import create_oauth_router, init_oauth, register_model
from myapp.models import MyBitcoinCashUser, MyOAuthToken

# Register custom models
register_model('user', MyBitcoinCashUser)
register_model('token', MyOAuthToken)

app = FastAPI()

@app.on_event("startup")
async def startup():
    await init_oauth()

app.include_router(create_oauth_router())
```

Or use environment variables:

```bash
export BITCOINCASH_OAUTH_USER_MODEL="myapp.models.MyBitcoinCashUser"
export BITCOINCASH_OAUTH_TOKEN_MODEL="myapp.models.MyOAuthToken"
```

Your custom models should inherit from the base models:

```python
# myapp/models.py
from bitcoincash_oauth_fastapi.models import BitcoinCashUser, OAuthToken

class MyBitcoinCashUser(BitcoinCashUser):
    __tablename__ = "my_custom_users"
    # Add your custom fields

class MyOAuthToken(OAuthToken):
    __tablename__ = "my_custom_tokens"
    # Add your custom fields
```

## Configuration Reference

| Parameter | Default | Description |
|-----------|---------|-------------|
| `router_prefix` | `"/auth"` | URL prefix for OAuth endpoints |
| `token_ttl` | `3600` | Access token lifetime (seconds) |
| `refresh_token_ttl` | `2592000` | Refresh token lifetime (seconds) |
| `max_tokens_per_user` | `5` | Maximum active tokens per user |
| `max_timestamp_diff` | `300` | Max timestamp age for replay protection |
| `require_signature_for_registration` | `false` | Require signature verification for registration |

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db

# Security
SECRET_KEY=your-secret-key-here
REQUIRE_SIGNATURE_FOR_REGISTRATION=true

# Token settings
ACCESS_TOKEN_LIFETIME=3600
REFRESH_TOKEN_LIFETIME=2592000
MAX_TOKENS_PER_USER=5
MAX_TIMESTAMP_DIFF=300
```

## Dependencies

- `fastapi>=0.100.0`
- `coincurve>=18.0.0`
- `cashaddress>=1.0.6`
- `python-jose>=3.3.0`
- `pydantic>=2.0.0`

## License

MIT
