"""
Bitcoin Cash ECDSA validation and address utilities
"""

import hashlib
import base58
from typing import Tuple, Optional
from coincurve import PublicKey


class BitcoinCashValidator:
    """Validator for Bitcoin Cash addresses and ECDSA signatures"""

    # Bitcoin network version bytes
    MAINNET_PUBKEY_HASH = 0x00
    TESTNET_PUBKEY_HASH = 0x6f

    @staticmethod
    def hash160(data: bytes) -> bytes:
        """RIPEMD160(SHA256(data))"""
        sha256_hash = hashlib.sha256(data).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        return ripemd160.digest()

    @staticmethod
    def hash256(data: bytes) -> bytes:
        """Double SHA256 hash"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @classmethod
    def public_key_to_address(
        cls, 
        public_key: bytes, 
        network: str = "mainnet"
    ) -> str:
        """
        Convert a public key to Bitcoin Cash address
        
        Args:
            public_key: Compressed (33 bytes) or uncompressed (65 bytes) public key
            network: "mainnet" or "testnet"
        
        Returns:
            Base58Check encoded Bitcoin address
        """
        # Get the public key hash (RIPEMD160(SHA256(pubkey)))
        pub_key_hash = cls.hash160(public_key)
        
        # Add version byte
        version = cls.MAINNET_PUBKEY_HASH if network == "mainnet" else cls.TESTNET_PUBKEY_HASH
        versioned_hash = bytes([version]) + pub_key_hash
        
        # Add checksum (first 4 bytes of double SHA256)
        checksum = cls.hash256(versioned_hash)[:4]
        binary_address = versioned_hash + checksum
        
        # Encode to Base58
        return base58.b58encode(binary_address).decode('ascii')

    @classmethod
    def validate_address(cls, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a Bitcoin Cash address
        
        Returns:
            Tuple of (is_valid, network or None)
        """
        try:
            decoded = base58.b58decode(address)
            
            if len(decoded) != 25:
                return False, None
            
            version = decoded[0]
            payload = decoded[:-4]
            checksum = decoded[-4:]
            
            # Verify checksum
            expected_checksum = cls.hash256(payload)[:4]
            if checksum != expected_checksum:
                return False, None
            
            # Determine network
            if version == cls.MAINNET_PUBKEY_HASH:
                return True, "mainnet"
            elif version == cls.TESTNET_PUBKEY_HASH:
                return True, "testnet"
            else:
                return False, None
                
        except Exception:
            return False, None

    @classmethod
    def verify_signature(
        cls,
        message: str,
        signature_hex: str,
        public_key_hex: str
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
            message_bytes = message.encode('utf-8')
            message_hash = hashlib.sha256(message_bytes).digest()
            
            # Parse public key
            public_key = PublicKey(bytes.fromhex(public_key_hex))
            
            # Parse DER signature
            signature = bytes.fromhex(signature_hex)
            
            # Verify the signature
            return public_key.verify(signature, message_hash, hasher=None)
            
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    @classmethod
    def authenticate_user(
        cls,
        user_id: str,
        timestamp: int,
        public_key_hex: str,
        signature_hex: str,
        expected_address: str,
        max_timestamp_diff: int = 300  # 5 minutes
    ) -> Tuple[bool, str]:
        """
        Full authentication flow validation
        
        Args:
            user_id: User identifier
            timestamp: Unix timestamp from client
            public_key_hex: Hex-encoded public key
            signature_hex: DER-encoded signature in hex
            expected_address: Expected Bitcoin Cash address for this user
            max_timestamp_diff: Maximum allowed time difference in seconds
        
        Returns:
            Tuple of (is_valid, reason)
        """
        import time
        
        # Check timestamp is recent (prevent replay attacks)
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff > max_timestamp_diff:
            return False, f"Timestamp too old (diff: {time_diff}s, max: {max_timestamp_diff}s)"
        
        # Reconstruct the message that was signed
        message = f"{user_id},{timestamp}"
        
        # Convert public key to address
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            derived_address = cls.public_key_to_address(public_key_bytes)
        except Exception as e:
            return False, f"Invalid public key: {str(e)}"
        
        # Verify address matches
        if derived_address != expected_address:
            return False, f"Address mismatch: derived {derived_address} != expected {expected_address}"
        
        # Verify signature
        if not cls.verify_signature(message, signature_hex, public_key_hex):
            return False, "Invalid signature"
        
        return True, "Authentication successful"


# Convenience functions
def verify_bitcoin_cash_auth(
    user_id: str,
    timestamp: int,
    public_key: str,
    signature: str,
    expected_address: str
) -> Tuple[bool, str]:
    """
    Convenience function for one-shot authentication verification
    
    Example:
        is_valid, message = verify_bitcoin_cash_auth(
            user_id="user_123",
            timestamp=1234567890,
            public_key="03...",
            signature="3045...",
            expected_address="1A..."
        )
    """
    return BitcoinCashValidator.authenticate_user(
        user_id, timestamp, public_key, signature, expected_address
    )


def public_key_to_address(public_key: str, network: str = "mainnet") -> str:
    """Convert hex public key to Bitcoin Cash address"""
    return BitcoinCashValidator.public_key_to_address(
        bytes.fromhex(public_key), 
        network
    )
