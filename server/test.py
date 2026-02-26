"""
Test script for Bitcoin Cash OAuth Server with CashAddr format
"""

import sys
import time
import hashlib

# Add parent directory to path for imports
sys.path.insert(0, ".")


def test_validator():
    """Test the BitcoinCashValidator class"""
    print("Testing BitcoinCashValidator with CashAddr format...")

    from validator import BitcoinCashValidator, public_key_to_cash_address

    # Test address validation
    print("\n1. Testing CashAddr validation:")

    # Valid CashAddr mainnet addresses
    test_addresses = [
        "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5",
        "bitcoincash:qz7f8z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z",
    ]

    for addr in test_addresses:
        is_valid, network = BitcoinCashValidator.validate_cash_address(addr)
        print(f"   Address: {addr}")
        print(f"   Valid: {is_valid}, Network: {network}")

    # Valid CashAddr testnet address
    testnet_addr = "bchtest:qqrxvhnn88gmpczyxry254vcsnl6canmkqvepqak5g"
    is_valid, network = BitcoinCashValidator.validate_cash_address(testnet_addr)
    print(f"\n   Testnet Address: {testnet_addr}")
    print(f"   Valid: {is_valid}, Network: {network}")

    # Invalid address
    invalid_address = "invalidaddress123"
    is_valid, network = BitcoinCashValidator.validate_cash_address(invalid_address)
    print(f"\n   Invalid address test: {is_valid}")

    # Legacy format (should fail with new validator)
    legacy_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    is_valid, network = BitcoinCashValidator.validate_cash_address(legacy_addr)
    print(f"   Legacy address (should fail): {legacy_addr}")
    print(f"   Valid: {is_valid}")

    # Test public key to CashAddr conversion
    print("\n2. Testing public key to CashAddr conversion:")
    # Example compressed public key (33 bytes)
    example_pubkey = (
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
    try:
        address = public_key_to_cash_address(example_pubkey, "mainnet")
        print(f"   Public Key: {example_pubkey[:20]}...")
        print(f"   CashAddr: {address}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n✅ Validator tests completed")


def test_token_manager():
    """Test the TokenManager class"""
    print("\nTesting TokenManager...")

    from token_manager import token_manager

    # Test user registration
    print("\n1. Testing user registration:")
    # CashAddr format addresses
    address = "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5"

    user_id = token_manager.register_user(address)
    print(f"   Registered user: {user_id}")
    print(f"   Address: {address}")

    # Register with custom ID
    custom_id = "my_custom_id_123"
    address2 = "bitcoincash:qz7f8z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z"
    user_id2 = token_manager.register_user(address2, custom_id)
    print(f"   Custom ID user: {user_id2}")

    # Test token creation
    print("\n2. Testing token creation:")
    token_data = token_manager.create_token_pair(user_id, scopes=["read", "write"])
    print(f"   Access Token: {token_data.access_token[:30]}...")
    print(f"   Refresh Token: {token_data.refresh_token[:30]}...")
    print(f"   Expires in: {token_data.expires_in} seconds")
    print(f"   Scopes: {token_data.scopes}")

    # Test token validation
    print("\n3. Testing token validation:")
    validated = token_manager.validate_access_token(token_data.access_token)
    if validated:
        print(f"   ✓ Token valid for user: {validated.user_id}")
    else:
        print("   ✗ Token invalid")

    # Test token info
    print("\n4. Testing token info:")
    info = token_manager.get_token_info(token_data.access_token)
    if info:
        print(f"   User: {info['user_id']}")
        print(f"   Scopes: {info['scopes']}")
        print(f"   Expires: {info['expires_at']}")

    print("\n✅ Token manager tests completed")


def test_authentication_flow():
    """Test the complete authentication flow"""
    print("\nTesting complete authentication flow...")

    from validator import verify_bitcoin_cash_auth
    from token_manager import token_manager

    # This would normally require a real signature
    print("\n1. Simulating authentication flow:")

    # Mock data (in real use, these come from the client)
    user_id = "test_user_123"
    timestamp = int(time.time())

    # Register a user first with CashAddr
    address = "bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5"
    registered_id = token_manager.register_user(address, user_id)
    print(f"   Registered user: {registered_id}")
    print(f"   Expected address: {address}")

    # In a real scenario, the client would:
    # 1. Create message: f"bitcoincash-oauth|{domain}|{user_id}|{timestamp}"
    # 2. Sign with private key
    # 3. Send public key and signature to server
    # Message format: protocol|domain|userId|timestamp (prevents cross-protocol replay)

    print("\n   Note: Real signature verification requires client-generated signatures")
    print("   This test demonstrates the flow structure.")
    print("\n   CashAddr Format: bitcoincash:<payload>")
    print("   Example: bitcoincash:qqrxvhnn88gmpczyxry254vcsnl6canmkqgt98lpn5")

    print("\n✅ Authentication flow test completed")


if __name__ == "__main__":
    print("=" * 60)
    print("Bitcoin Cash OAuth Server Tests (CashAddr Format)")
    print("=" * 60)

    try:
        test_validator()
        test_token_manager()
        test_authentication_flow()

        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)
        print("\nTo run the server:")
        print("  cd server && uv pip install -r requirements.txt && python main.py")
        print("\nTo test with live server:")
        print("  cd client && npm install && node test.js")

    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        print("Please install dependencies first:")
        print("  cd server && uv pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
