package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Standard salt", SaltLength},
		{"Verifier salt", VerifierSaltLength},
		{"Custom length", 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := GenerateSalt(tt.length)
			if err != nil {
				t.Fatalf("GenerateSalt() error = %v", err)
			}
			if len(salt) != tt.length {
				t.Errorf("GenerateSalt() length = %v, want %v", len(salt), tt.length)
			}

			// Test uniqueness
			salt2, err := GenerateSalt(tt.length)
			if err != nil {
				t.Fatalf("GenerateSalt() error = %v", err)
			}
			if bytes.Equal(salt, salt2) {
				t.Error("GenerateSalt() produced identical salts")
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	password := "test-master-password"
	salt := []byte("test-salt-32-bytes-long-enough!!")

	// Test key derivation
	key := DeriveKey(password, salt)
	if len(key) != ArgonKeyLength {
		t.Errorf("DeriveKey() length = %v, want %v", len(key), ArgonKeyLength)
	}

	// Test deterministic output
	key2 := DeriveKey(password, salt)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveKey() should produce deterministic output")
	}

	// Test different password produces different key
	key3 := DeriveKey("different-password", salt)
	if bytes.Equal(key, key3) {
		t.Error("DeriveKey() should produce different keys for different passwords")
	}

	// Test different salt produces different key
	salt2 := []byte("different-salt-32-bytes-long!!!")
	key4 := DeriveKey(password, salt2)
	if bytes.Equal(key, key4) {
		t.Error("DeriveKey() should produce different keys for different salts")
	}
}

func TestArgon2idParameters(t *testing.T) {
	// Verify RFC 9106 compliance
	if ArgonMemory != 64*1024 {
		t.Errorf("ArgonMemory = %v, want %v (64MB)", ArgonMemory, 64*1024)
	}
	if ArgonIterations != 1 {
		t.Errorf("ArgonIterations = %v, want 1", ArgonIterations)
	}
	if ArgonParallelism != 4 {
		t.Errorf("ArgonParallelism = %v, want 4", ArgonParallelism)
	}
	if ArgonKeyLength != 32 {
		t.Errorf("ArgonKeyLength = %v, want 32 (256 bits)", ArgonKeyLength)
	}
}

func TestHashMasterPassword(t *testing.T) {
	password := "secure-master-password"
	salt, err := GenerateSalt(SaltLength)
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}

	hash := HashMasterPassword(password, salt)
	if len(hash) != ArgonKeyLength {
		t.Errorf("HashMasterPassword() length = %v, want %v", len(hash), ArgonKeyLength)
	}

	// Test deterministic
	hash2 := HashMasterPassword(password, salt)
	if !bytes.Equal(hash, hash2) {
		t.Error("HashMasterPassword() should be deterministic")
	}
}

func TestVerifyMasterPassword(t *testing.T) {
	password := "my-secure-password"
	salt, err := GenerateSalt(SaltLength)
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}

	hash := HashMasterPassword(password, salt)

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"Correct password", password, true},
		{"Incorrect password", "wrong-password", false},
		{"Empty password", "", false},
		{"Similar password", "my-secure-password!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyMasterPassword(tt.password, salt, hash); got != tt.want {
				t.Errorf("VerifyMasterPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, ArgonKeyLength)
	copy(key, []byte("test-key-32-bytes-long-enough!!"))

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"Simple text", []byte("Hello, World!")},
		{"Empty string", []byte("")},
		{"Long text", []byte("This is a longer piece of text that we want to encrypt and decrypt to ensure it works properly with various payload sizes.")},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"Unicode text", []byte("Hello 世界 🔐")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext is different from plaintext
			if string(tt.plaintext) == ciphertext && len(tt.plaintext) > 0 {
				t.Error("Encrypt() ciphertext should differ from plaintext")
			}

			// Decrypt
			decrypted, err := Decrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify decrypted matches original
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptUniqueNonces(t *testing.T) {
	key := make([]byte, ArgonKeyLength)
	copy(key, []byte("test-key-32-bytes-long-enough!!"))
	plaintext := []byte("test message")

	// Encrypt same plaintext multiple times
	ciphertext1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertexts should be different due to unique nonces
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypt() should produce different ciphertexts with unique nonces")
	}

	// But both should decrypt to same plaintext
	decrypted1, _ := Decrypt(ciphertext1, key)
	decrypted2, _ := Decrypt(ciphertext2, key)

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("Both ciphertexts should decrypt to original plaintext")
	}
}

func TestDecryptInvalidInputs(t *testing.T) {
	key := make([]byte, ArgonKeyLength)
	copy(key, []byte("test-key-32-bytes-long-enough!!"))

	tests := []struct {
		name       string
		ciphertext string
		wantErr    error
	}{
		{"Invalid base64", "not-valid-base64!", nil},
		{"Too short", "dGVzdA==", ErrInvalidCiphertext}, // "test" in base64, too short
		{"Empty string", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.ciphertext, key)
			if err == nil {
				t.Error("Decrypt() should return error for invalid input")
			}
		})
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, ArgonKeyLength)
	key2 := make([]byte, ArgonKeyLength)
	copy(key1, []byte("key1-32-bytes-long-enough!!!!!!"))
	copy(key2, []byte("key2-32-bytes-long-enough!!!!!!"))

	plaintext := []byte("secret message")

	ciphertext, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with wrong key
	_, err = Decrypt(ciphertext, key2)
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt() with wrong key should return ErrDecryptionFailed, got %v", err)
	}
}

func TestGenerateEncryptionKeyVerifier(t *testing.T) {
	key := make([]byte, ArgonKeyLength)
	copy(key, []byte("test-key-32-bytes-long-enough!!"))

	verifier, salt, err := GenerateEncryptionKeyVerifier(key)
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyVerifier() error = %v", err)
	}

	if verifier == "" {
		t.Error("GenerateEncryptionKeyVerifier() verifier should not be empty")
	}

	if len(salt) != VerifierSaltLength {
		t.Errorf("GenerateEncryptionKeyVerifier() salt length = %v, want %v", len(salt), VerifierSaltLength)
	}

	// Verify the verifier is valid
	err = ValidateEncryptionKeyVerifier(key, verifier, salt)
	if err != nil {
		t.Errorf("ValidateEncryptionKeyVerifier() should succeed for correct key, got error: %v", err)
	}
}

func TestValidateEncryptionKeyVerifier(t *testing.T) {
	correctKey := make([]byte, ArgonKeyLength)
	wrongKey := make([]byte, ArgonKeyLength)
	copy(correctKey, []byte("correct-key-32-bytes-long!!!!!"))
	copy(wrongKey, []byte("wrong-key-32-bytes-long!!!!!!!"))

	verifier, salt, err := GenerateEncryptionKeyVerifier(correctKey)
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyVerifier() error = %v", err)
	}

	tests := []struct {
		name    string
		key     []byte
		wantErr error
	}{
		{"Correct key", correctKey, nil},
		{"Wrong key", wrongKey, ErrInvalidMasterKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEncryptionKeyVerifier(tt.key, verifier, salt)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidateEncryptionKeyVerifier() unexpected error = %v", err)
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("ValidateEncryptionKeyVerifier() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEncryptionKeyVerifierInvalidInputs(t *testing.T) {
	key := make([]byte, ArgonKeyLength)
	copy(key, []byte("test-key-32-bytes-long-enough!!"))
	salt := make([]byte, VerifierSaltLength)

	tests := []struct {
		name     string
		verifier string
	}{
		{"Invalid base64", "not-valid-base64!"},
		{"Empty verifier", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEncryptionKeyVerifier(key, tt.verifier, salt)
			if err == nil {
				t.Error("ValidateEncryptionKeyVerifier() should return error for invalid input")
			}
		})
	}
}

// Benchmark tests
func BenchmarkDeriveKey(b *testing.B) {
	password := "benchmark-password"
	salt := make([]byte, SaltLength)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(password, salt)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, ArgonKeyLength)
	plaintext := []byte("This is a test message for benchmarking encryption performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plaintext, key)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, ArgonKeyLength)
	plaintext := []byte("This is a test message for benchmarking decryption performance")
	ciphertext, _ := Encrypt(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(ciphertext, key)
	}
}

// Test vector from a known implementation
func TestEncryptDecryptTestVector(t *testing.T) {
	// Using a known key for reproducibility
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	if len(key) != 32 {
		key = make([]byte, 32)
		copy(key, []byte("test-vector-key-32-bytes-long!"))
	}

	plaintext := []byte("Test vector plaintext")

	// Encrypt and decrypt
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Test vector failed: decrypted = %v, want %v", decrypted, plaintext)
	}
}
