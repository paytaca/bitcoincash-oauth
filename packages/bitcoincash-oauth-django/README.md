# Bitcoin Cash OAuth - Django

Bitcoin Cash OAuth authentication for Django and Django REST Framework (DRF).

## Installation

```bash
pip install bitcoincash-oauth-django
```

Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    'bitcoincash_oauth_django',
]
```

## Django Views Usage

### URL Configuration

```python
# urls.py
from django.urls import path
from bitcoincash_oauth_django import register, token, refresh, revoke, me

urlpatterns = [
    path('auth/register', register, name='register'),
    path('auth/token', token, name='token'),
    path('auth/refresh', refresh, name='refresh'),
    path('auth/revoke', revoke, name='revoke'),
    path('auth/me', me, name='me'),
]
```

### Custom View Instance

```python
# urls.py
from django.urls import path
from bitcoincash_oauth_django import BitcoinCashOAuthViews

oauth = BitcoinCashOAuthViews(
    token_ttl=3600,
    refresh_token_ttl=2592000,
    max_tokens_per_user=5
)

urlpatterns = [
    path('auth/register', oauth.register_view, name='register'),
    path('auth/token', oauth.token_view, name='token'),
    path('auth/refresh', oauth.refresh_view, name='refresh'),
    path('auth/revoke', oauth.revoke_view, name='revoke'),
    path('auth/me', oauth.me_view, name='me'),
]
```

## Django REST Framework Usage

### URL Configuration

```python
# urls.py
from django.urls import path
from bitcoincash_oauth_django.drf import (
    RegisterView, TokenView, RefreshView, RevokeView, MeView
)

urlpatterns = [
    path('auth/register', RegisterView.as_view(), name='register'),
    path('auth/token', TokenView.as_view(), name='token'),
    path('auth/refresh', RefreshView.as_view(), name='refresh'),
    path('auth/revoke', RevokeView.as_view(), name='revoke'),
    path('auth/me', MeView.as_view(), name='me'),
]
```

### Protecting Views with DRF

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from bitcoincash_oauth_django.drf import IsBitcoinCashAuthenticated, HasScope

class ProtectedView(APIView):
    permission_classes = [IsBitcoinCashAuthenticated]
    
    def get(self, request):
        # Access token data from request
        user_id = request.token_data.user_id
        scopes = request.token_data.scopes
        
        return Response({
            "user_id": user_id,
            "scopes": scopes,
            "message": "This is a protected resource"
        })

class AdminView(APIView):
    permission_classes = [IsBitcoinCashAuthenticated, HasScope]
    required_scopes = ["admin"]
    
    def get(self, request):
        return Response({"message": "Admin only"})
```

### Using with ViewSets

```python
from rest_framework import viewsets
from rest_framework.decorators import action
from bitcoincash_oauth_django.drf import IsBitcoinCashAuthenticated

class MyViewSet(viewsets.ViewSet):
    permission_classes = [IsBitcoinCashAuthenticated]
    
    def list(self, request):
        user_id = request.token_data.user_id
        return Response({"user_id": user_id, "items": []})
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

Obtain an OAuth token using Bitcoin Cash signature.

**Request:**
```json
{
  "user_id": "user_abc123",
  "timestamp": 1234567890,
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

## Advanced Usage

### Using the Validator Directly

```python
from bitcoincash_oauth_django import BitcoinCashValidator, verify_bitcoin_cash_auth

# Validate a CashAddr
is_valid, network = BitcoinCashValidator.validate_cash_address(
    "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5"
)

# Verify authentication
is_valid, reason = verify_bitcoin_cash_auth(
    user_id="user_123",
    timestamp=1234567890,
    public_key="0279BE...",
    signature="3045...",
    expected_address="bitcoincash:qz7f..."
)

# Convert public key to address
address = BitcoinCashValidator.public_key_to_cash_address(
    bytes.fromhex("0279BE..."),
    network="mainnet"
)
```

### Custom Token Manager

```python
from bitcoincash_oauth_django import TokenManager, token_manager

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

## DRF Permission Classes

| Permission Class | Description |
|------------------|-------------|
| `IsBitcoinCashAuthenticated` | Validates Bearer token and attaches token_data to request |
| `HasScope` | Checks if user has required OAuth scopes |

## Configuration

```python
# settings.py

# Optional: Configure token settings
BITCOINCASH_OAUTH = {
    'TOKEN_TTL': 3600,  # 1 hour
    'REFRESH_TOKEN_TTL': 2592000,  # 30 days
    'MAX_TOKENS_PER_USER': 5,
}
```

## Dependencies

- `django>=4.0`
- `djangorestframework>=3.14.0`
- `coincurve>=18.0.0`
- `cashaddress>=1.0.6`
- `PyJWT>=2.8.0`

## License

MIT
