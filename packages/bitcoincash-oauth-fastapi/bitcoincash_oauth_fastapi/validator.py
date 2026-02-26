"""
Bitcoin Cash OAuth FastAPI - Core validator module
Bitcoin Cash ECDSA validation and address utilities with CashAddr format support
"""

import hashlib
from typing import Tuple, Optional
from coincurve import PublicKey
from cashaddress.convert import Address


class BitcoinCashValidator:
    """Validator for Bitcoin Cash addresses (CashAddr format) and ECDSA signatures"""

    @staticmethod
    def hash160(data: bytes) -> bytes:
        """RIPEMD160(SHA256(data))"""
        sha256_hash = hashlib.sha256(data).digest()
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_hash)
        return ripemd160.digest()

    @staticmethod
    def hash256(data: bytes) -> bytes:
        """Double SHA256 hash"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @classmethod
    def public_key_to_cash_address(
        cls, public_key: bytes, network: str = "mainnet"
    ) -> str:
        """
        Convert a public key to Bitcoin Cash CashAddr format

        Args:
            public_key: Compressed (33 bytes) or uncompressed (65 bytes) public key
            network: "mainnet" or "testnet"

        Returns:
            CashAddr format address (e.g., bitcoincash:qz7f... or bchtest:qz7f...)
        """
        from cashaddress.convert import Address

        # Get the public key hash (RIPEMD160(SHA256(pubkey)))
        pub_key_hash = cls.hash160(public_key)

        # Convert hash bytes to list for cashaddress library
        payload = list(pub_key_hash)

        # Determine prefix
        prefix = "bitcoincash" if network == "mainnet" else "bchtest"

        # Create Address object (P2PKH = version 0)
        addr = Address(version=0, payload=payload, prefix=prefix)

        return addr.cash_address()

    @classmethod
    def validate_cash_address(cls, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a Bitcoin Cash CashAddr format address

        Returns:
            Tuple of (is_valid, network or None)
            Network will be "mainnet", "testnet", or None
        """
        try:
            # Parse the CashAddr
            addr = Address.from_string(address)

            # Determine network from prefix
            if addr.prefix == "bitcoincash":
                return True, "mainnet"
            elif addr.prefix == "bchtest":
                return True, "testnet"
            elif addr.prefix == "bchreg":
                return True, "regtest"
            else:
                return True, addr.prefix

        except Exception:
            return False, None

    @classmethod
    def verify_signature(
        cls, message: str, signature_hex: str, public_key_hex: str
    ) -> bool:
        """
        Verify an ECDSA signature

        Args:
            message: The original message that was signed
            signature_hex: DER-encoded signature in hex
            public_key_hex: Public key in hex (compressed or uncompressed)

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Hash the message (same as client-side)
            message_bytes = message.encode("utf-8")
            message_hash = hashlib.sha256(message_bytes).digest()

            # Parse public key
            public_key = PublicKey(bytes.fromhex(public_key_hex))

            # Parse DER signature
            signature = bytes.fromhex(signature_hex)

            # Verify the signature
            return public_key.verify(signature, message_hash, hasher=None)

        except Exception as e:
            return False

    @classmethod
    def authenticate_user(
        cls,
        user_id: str,
        timestamp: int,
        public_key_hex: str,
        signature_hex: str,
        expected_address: str,
        domain: str = "oauth",
        max_timestamp_diff: int = 300,  # 5 minutes
    ) -> Tuple[bool, str]:
        """
        Full authentication flow validation

        Args:
            user_id: User identifier
            timestamp: Unix timestamp from client
            public_key_hex: Hex-encoded public key
            signature_hex: DER-encoded signature in hex
            expected_address: Expected Bitcoin Cash CashAddr address for this user
            domain: Domain/host for message binding (prevents phishing)
            max_timestamp_diff: Maximum allowed time difference in seconds

        Returns:
            Tuple of (is_valid, reason)
        """
        import time

        # Check timestamp is recent (prevent replay attacks)
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)

        if time_diff > max_timestamp_diff:
            return (
                False,
                f"Timestamp too old (diff: {time_diff}s, max: {max_timestamp_diff}s)",
            )

        # Validate expected address format
        is_valid_addr, network = cls.validate_cash_address(expected_address)
        if not is_valid_addr:
            return False, f"Invalid CashAddr format: {expected_address}"

        # Default to mainnet if network is None
        network = network or "mainnet"

        # Reconstruct the message that was signed (protocol|domain|userId|timestamp)
        message = f"bitcoincash-oauth|{domain}|{user_id}|{timestamp}"

        # Convert public key to CashAddr
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            derived_address = cls.public_key_to_cash_address(public_key_bytes, network)
        except Exception as e:
            return False, f"Invalid public key: {str(e)}"

        # Verify address matches (normalize case for comparison)
        if derived_address.lower() != expected_address.lower():
            return (
                False,
                f"Address mismatch: derived {derived_address} != expected {expected_address}",
            )

        # Verify signature
        if not cls.verify_signature(message, signature_hex, public_key_hex):
            return False, "Invalid signature"

        return True, "Authentication successful"


def verify_bitcoin_cash_auth(
    user_id: str,
    timestamp: int,
    public_key: str,
    signature: str,
    expected_address: str,
    domain: str = "oauth",
) -> Tuple[bool, str]:
    """
    Convenience function for one-shot authentication verification

    Example:
        is_valid, message = verify_bitcoin_cash_auth(
            user_id="user_123",
            timestamp=1234567890,
            public_key="03...",
            signature="3045...",
            expected_address="bitcoincash:qz7f...",
            domain="app.example.com"
        )
    """
    return BitcoinCashValidator.authenticate_user(
        user_id, timestamp, public_key, signature, expected_address, domain
    )


def public_key_to_cash_address(public_key: str, network: str = "mainnet") -> str:
    """Convert hex public key to Bitcoin Cash CashAddr format"""
    return BitcoinCashValidator.public_key_to_cash_address(
        bytes.fromhex(public_key), network
    )
