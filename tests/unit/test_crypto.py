"""Unit tests for darkhole.crypto module."""

import pytest

from darkhole.crypto import Cryptography, KeyPair, Ciphertext, CryptoError


class TestKeyPair:
    """Test KeyPair dataclass."""
    
    def test_keypair_creation(self):
        """Test creating a key pair."""
        public_key = b"public_key_data"
        private_key = b"private_key_data"
        
        keypair = KeyPair(
            public_key=public_key,
            private_key=private_key
        )
        
        assert keypair.public_key == public_key
        assert keypair.private_key == private_key


class TestCiphertext:
    """Test Ciphertext dataclass."""
    
    def test_ciphertext_creation(self):
        """Test creating ciphertext."""
        data = b"encrypted_data"
        nonce = b"random_nonce"
        tag = b"auth_tag"
        
        ciphertext = Ciphertext(
            data=data,
            nonce=nonce,
            tag=tag
        )
        
        assert ciphertext.data == data
        assert ciphertext.nonce == nonce
        assert ciphertext.tag == tag
    
    def test_ciphertext_creation_without_tag(self):
        """Test creating ciphertext without tag."""
        data = b"encrypted_data"
        nonce = b"random_nonce"
        
        ciphertext = Ciphertext(
            data=data,
            nonce=nonce
        )
        
        assert ciphertext.data == data
        assert ciphertext.nonce == nonce
        assert ciphertext.tag is None


class TestCryptoError:
    """Test CryptoError exception."""
    
    def test_crypto_error_inheritance(self):
        """Test that CryptoError inherits from Exception."""
        error = CryptoError("Test error")
        assert isinstance(error, Exception)
    
    def test_crypto_error_message(self):
        """Test CryptoError message."""
        error_message = "Cryptographic operation failed"
        error = CryptoError(error_message)
        assert str(error) == error_message


class TestCryptography:
    """Test Cryptography class."""
    
    @pytest.fixture
    def crypto(self):
        """Create a cryptography instance for testing."""
        return Cryptography()
    
    def test_initialization(self, crypto):
        """Test cryptography module initialization."""
        assert crypto is not None
    
    def test_generate_keypair_default(self, crypto):
        """Test generating default key pair."""
        keypair = crypto.generate_keypair()
        
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 32
        assert len(keypair.private_key) == 32
        assert keypair.public_key != keypair.private_key
    
    def test_generate_keypair_x25519(self, crypto):
        """Test generating X25519 key pair."""
        keypair = crypto.generate_keypair("x25519")
        
        assert isinstance(keypair, KeyPair)
        assert len(keypair.public_key) == 32
        assert len(keypair.private_key) == 32
    
    def test_generate_keypair_unsupported_type(self, crypto):
        """Test generating key pair with unsupported type."""
        with pytest.raises(Exception):  # Will raise due to unimplemented actual crypto
            crypto.generate_keypair("unsupported")
    
    def test_derive_shared_secret(self, crypto):
        """Test deriving shared secret."""
        private_key = b"private_key_32_bytes_long!!!"
        peer_public_key = b"peer_public_32_bytes_long!!!"
        
        secret = crypto.derive_shared_secret(private_key, peer_public_key)
        
        assert isinstance(secret, bytes)
        assert len(secret) == 32  # SHA256 output
    
    def test_derive_shared_secret_empty_keys(self, crypto):
        """Test deriving shared secret with empty keys."""
        secret = crypto.derive_shared_secret(b"", b"")
        
        assert isinstance(secret, bytes)
        assert len(secret) == 32
    
    def test_encrypt_message_string(self, crypto):
        """Test encrypting a string message."""
        message = "Hello, Darkhole!"
        key = b"encryption_key_32_bytes_long!"
        
        ciphertext = crypto.encrypt_message(message, key)
        
        assert isinstance(ciphertext, Ciphertext)
        assert len(ciphertext.nonce) == 12  # Nonce length
        assert len(ciphertext.data) > 0
    
    def test_encrypt_message_bytes(self, crypto):
        """Test encrypting bytes message."""
        message = b"Binary message data"
        key = b"encryption_key_32_bytes_long!"
        
        ciphertext = crypto.encrypt_message(message, key)
        
        assert isinstance(ciphertext, Ciphertext)
        assert isinstance(ciphertext.data, bytes)
    
    def test_decrypt_message(self, crypto):
        """Test decrypting a message."""
        original_message = "Secret message"
        key = b"encryption_key_32_bytes_long!"
        
        # Encrypt first
        ciphertext = crypto.encrypt_message(original_message, key)
        
        # Then decrypt
        decrypted = crypto.decrypt_message(ciphertext, key)
        
        assert isinstance(decrypted, bytes)
        assert decrypted == original_message.encode('utf-8')
    
    def test_decrypt_invalid_ciphertext(self, crypto):
        """Test decrypting with wrong key."""
        original_message = "Secret message"
        correct_key = b"correct_key_32_bytes_long!!"
        wrong_key = b"wrong_key_32_bytes_long!!!"
        
        # Encrypt with correct key
        ciphertext = crypto.encrypt_message(original_message, correct_key)
        
        # Try to decrypt with wrong key
        decrypted = crypto.decrypt_message(ciphertext, wrong_key)
        
        # Should get different data (though not necessarily garbage due to simple demo crypto)
        assert decrypted != original_message.encode('utf-8')
    
    def test_hash_data_sha256(self, crypto):
        """Test hashing data with SHA256."""
        data = "test data for hashing"
        
        hash_result = crypto.hash_data(data, "sha256")
        
        assert isinstance(hash_result, bytes)
        assert len(hash_result) == 32  # SHA256 output length
    
    def test_hash_data_sha512(self, crypto):
        """Test hashing data with SHA512."""
        data = "test data for hashing"
        
        hash_result = crypto.hash_data(data, "sha512")
        
        assert isinstance(hash_result, bytes)
        assert len(hash_result) == 64  # SHA512 output length
    
    def test_hash_data_string_vs_bytes(self, crypto):
        """Test hashing string vs bytes gives same result."""
        data_str = "test data"
        data_bytes = b"test data"
        
        hash_str = crypto.hash_data(data_str)
        hash_bytes = crypto.hash_data(data_bytes)
        
        assert hash_str == hash_bytes
    
    def test_hash_data_unsupported_algorithm(self, crypto):
        """Test hashing with unsupported algorithm."""
        data = "test data"
        
        with pytest.raises(CryptoError, match="Unsupported hash algorithm"):
            crypto.hash_data(data, "md5")
    
    def test_generate_nonce_default_length(self, crypto):
        """Test generating nonce with default length."""
        nonce = crypto.generate_nonce()
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12
    
    def test_generate_nonce_custom_length(self, crypto):
        """Test generating nonce with custom length."""
        length = 16
        nonce = crypto.generate_nonce(length)
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == length
    
    def test_generate_nonce_zero_length(self, crypto):
        """Test generating nonce with zero length."""
        nonce = crypto.generate_nonce(0)
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == 0