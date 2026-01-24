package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters per RFC 9106
	ArgonMemory      = 64 * 1024 // 64 MB in KiB
	ArgonIterations  = 1
	ArgonParallelism = 4
	ArgonKeyLength   = 32 // 256 bits for AES-256

	// Salt lengths
	SaltLength         = 32 // 256 bits
	VerifierSaltLength = 32

	// AES-GCM nonce size
	NonceSize = 12 // 96 bits (standard for GCM)
)

var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrInvalidVerifier   = errors.New("invalid encryption key verifier")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidMasterKey  = errors.New("invalid master key")
)

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives an encryption key from a master password using Argon2id
// Parameters follow RFC 9106 recommendations
func DeriveKey(masterPassword string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(masterPassword),
		salt,
		ArgonIterations,
		ArgonMemory,
		ArgonParallelism,
		ArgonKeyLength,
	)
}

// HashMasterPassword hashes the master password for authentication verification
// This is separate from the encryption key derivation
func HashMasterPassword(masterPassword string, salt []byte) []byte {
	// Use same Argon2id parameters for consistency
	return argon2.IDKey(
		[]byte(masterPassword),
		salt,
		ArgonIterations,
		ArgonMemory,
		ArgonParallelism,
		ArgonKeyLength,
	)
}

// VerifyMasterPassword verifies a master password against its hash
func VerifyMasterPassword(masterPassword string, salt []byte, expectedHash []byte) bool {
	hash := HashMasterPassword(masterPassword, salt)
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}

// GenerateEncryptionKeyVerifier creates a verifier value to confirm encryption key validity
// This allows us to detect incorrect master passwords before attempting decryption
func GenerateEncryptionKeyVerifier(encryptionKey []byte) (verifier string, salt []byte, err error) {
	// Generate a random salt for the verifier (returned for storage, not used in encryption)
	salt, err = GenerateSalt(VerifierSaltLength)
	if err != nil {
		return "", nil, err
	}

	// Generate a nonce for encryption
	nonce, err := GenerateSalt(NonceSize)
	if err != nil {
		return "", nil, err
	}

	// Create a simple known plaintext
	plaintext := []byte("keyper-encryption-key-verifier")

	// Encrypt it with the encryption key
	ciphertext, err := encryptAESGCM(plaintext, encryptionKey, nonce)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Return base64-encoded ciphertext as verifier
	verifier = base64.StdEncoding.EncodeToString(ciphertext)
	return verifier, salt, nil
}

// ValidateEncryptionKeyVerifier checks if an encryption key is valid by attempting to decrypt the verifier
func ValidateEncryptionKeyVerifier(encryptionKey []byte, verifier string, salt []byte) error {
	// Decode the verifier
	ciphertext, err := base64.StdEncoding.DecodeString(verifier)
	if err != nil {
		return ErrInvalidVerifier
	}

	// Extract nonce from ciphertext
	if len(ciphertext) < NonceSize {
		return ErrInvalidVerifier
	}

	nonce := ciphertext[:NonceSize]

	// Try to decrypt it
	plaintext, err := decryptAESGCM(ciphertext, encryptionKey, nonce)
	if err != nil {
		return ErrInvalidMasterKey
	}

	// Verify the plaintext matches expected value
	expected := []byte("keyper-encryption-key-verifier")
	if subtle.ConstantTimeCompare(plaintext, expected) != 1 {
		return ErrInvalidVerifier
	}

	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the provided key
// Returns base64-encoded ciphertext with nonce prepended
func Encrypt(plaintext []byte, key []byte) (string, error) {
	// Generate a unique nonce
	nonce, err := GenerateSalt(NonceSize)
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptAESGCM(plaintext, key, nonce)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM
func Decrypt(ciphertextB64 string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	// Extract nonce (first NonceSize bytes)
	if len(ciphertext) < NonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce := ciphertext[:NonceSize]
	actualCiphertext := ciphertext[NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// encryptAESGCM performs the actual AES-GCM encryption
// Nonce is prepended to the ciphertext
func encryptAESGCM(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt and prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAESGCM performs the actual AES-GCM decryption
// Expects nonce to be prepended to ciphertext
func decryptAESGCM(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// The ciphertext already has the nonce prepended, so extract actual ciphertext
	actualCiphertext := ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
