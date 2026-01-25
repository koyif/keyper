package commands

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// setupCardTest creates a test environment for card commands
func setupCardTest(t *testing.T) (*config.Config, *session.Session, storage.Repository) {
	t.Helper()

	// Create config
	cfg := config.DefaultConfig()

	// Create session with encryption key
	sess := session.New("")
	salt, _ := crypto.GenerateSalt(crypto.SaltLength)
	encryptionKey := crypto.DeriveKey("test-password", salt)
	sess.SetEncryptionKey(encryptionKey)
	sess.UserID = "test-user-id"

	// Create in-memory storage
	repo, err := storage.NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	t.Cleanup(func() {
		repo.Close()
	})

	return cfg, sess, repo
}

func TestCardCommands(t *testing.T) {
	cfg, sess, repo := setupCardTest(t)
	encryptionKey := sess.GetEncryptionKey()

	getCfg := func() *config.Config { return cfg }
	getSess := func() *session.Session { return sess }
	getStorage := func() (storage.Repository, error) { return repo, nil }

	ctx := context.Background()

	t.Run("CardAdd", func(t *testing.T) {
		// Create card
		cardData := &pb.BankCardData{
			CardholderName: "John Doe",
			CardNumber:     "4532 0151 1283 0366", // Valid test card number (passes Luhn)
			ExpiryMonth:    "12",
			ExpiryYear:     "2025",
			Cvv:            "123",
			Pin:            "1234",
			BankName:       "Test Bank",
		}

		cardJSON, err := protojson.Marshal(cardData)
		if err != nil {
			t.Fatalf("Failed to marshal card data: %v", err)
		}

		encryptedData, err := crypto.Encrypt(cardJSON, encryptionKey)
		if err != nil {
			t.Fatalf("Failed to encrypt card data: %v", err)
		}

		cardMeta := CardMetadata{
			Last4Digits: "0366",
			BankName:    "Test Bank",
			Notes:       "Test card",
		}
		metadataJSON, err := json.Marshal(cardMeta)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		now := time.Now()
		secret := &storage.LocalSecret{
			ID:             "test-card-1",
			Name:           "My Test Card",
			Type:           pb.SecretType_SECRET_TYPE_BANK_CARD,
			EncryptedData:  []byte(encryptedData),
			Nonce:          []byte{}, // Nonce embedded in encrypted data
			Metadata:       string(metadataJSON),
			Version:        1,
			IsDeleted:      false,
			SyncStatus:     storage.SyncStatusPending,
			ServerVersion:  0,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		}

		err = repo.Create(ctx, secret)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Verify it was stored
		retrieved, err := repo.Get(ctx, "test-card-1")
		if err != nil {
			t.Fatalf("Failed to retrieve secret: %v", err)
		}
		if retrieved.Name != "My Test Card" {
			t.Errorf("Expected name 'My Test Card', got %s", retrieved.Name)
		}
		if retrieved.Type != pb.SecretType_SECRET_TYPE_BANK_CARD {
			t.Errorf("Expected type BANK_CARD, got %v", retrieved.Type)
		}
	})

	t.Run("CardGet", func(t *testing.T) {
		secret, err := repo.Get(ctx, "test-card-1")
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		var cardData pb.BankCardData
		err = protojson.Unmarshal(decryptedData, &cardData)
		if err != nil {
			t.Fatalf("Failed to unmarshal card data: %v", err)
		}

		if cardData.CardholderName != "John Doe" {
			t.Errorf("Expected cardholder 'John Doe', got %s", cardData.CardholderName)
		}
		if cardData.CardNumber != "4532 0151 1283 0366" {
			t.Errorf("Expected card number, got %s", cardData.CardNumber)
		}
		if cardData.BankName != "Test Bank" {
			t.Errorf("Expected bank 'Test Bank', got %s", cardData.BankName)
		}

		// Check metadata
		var cardMeta CardMetadata
		err = json.Unmarshal([]byte(secret.Metadata), &cardMeta)
		if err != nil {
			t.Fatalf("Failed to unmarshal metadata: %v", err)
		}
		if cardMeta.Last4Digits != "0366" {
			t.Errorf("Expected last 4 digits '0366', got %s", cardMeta.Last4Digits)
		}
	})

	t.Run("CardCommandGroup", func(t *testing.T) {
		cardCmd := NewCardCommands(getCfg, getSess, getStorage)
		if cardCmd == nil {
			t.Fatal("Expected card command group, got nil")
		}
		if cardCmd.Use != "card" {
			t.Errorf("Expected use 'card', got %s", cardCmd.Use)
		}

		// Verify all subcommands are registered
		subcommands := cardCmd.Commands()
		if len(subcommands) != 5 {
			t.Errorf("Expected 5 subcommands, got %d", len(subcommands))
		}
	})
}

func TestLuhnValidation(t *testing.T) {
	tests := []struct {
		name        string
		cardNumber  string
		shouldError bool
	}{
		{"Valid Visa", "4532 0151 1283 0366", false},
		{"Valid Visa (no spaces)", "4532015112830366", false},
		{"Valid Mastercard", "5425 2334 3010 9903", false},
		{"Valid Amex", "3782 822463 10005", false},
		{"Valid Discover", "6011 1111 1111 1117", false},
		{"Invalid checksum", "4532 0151 1283 0367", true},
		{"Too short", "4532 1488", true},
		{"Too long", "4532 0151 1283 0366 1234", true},
		{"Contains letters", "4532 015A 1283 0366", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCardNumber(tt.cardNumber)
			if tt.shouldError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.cardNumber)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error for %s, got %v", tt.cardNumber, err)
			}
		})
	}
}

func TestCardNumberFormatting(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Already formatted", "4532 1488 0343 6467", "4532 1488 0343 6467"},
		{"No spaces", "4532148803436467", "4532 1488 0343 6467"},
		{"With dashes", "4532-1488-0343-6467", "4532 1488 0343 6467"},
		{"Mixed formatting", "4532 1488-03436467", "4532 1488 0343 6467"},
		{"Amex (15 digits)", "378282246310005", "3782 8224 6310 005"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatCardNumber(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetLast4Digits(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"With spaces", "4532 1488 0343 6467", "6467"},
		{"No spaces", "4532148803436467", "6467"},
		{"With dashes", "4532-1488-0343-6467", "6467"},
		{"Short number", "123", "123"},
		{"Exactly 4 digits", "1234", "1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLast4Digits(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
