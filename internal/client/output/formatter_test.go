package output

import (
	"strings"
	"testing"
	"time"

	pb "github.com/koy/keyper/pkg/api/proto"
)

func TestJSONFormatter(t *testing.T) {
	formatter := NewJSONFormatter()

	// Test Format with CredentialView
	cred := &CredentialView{
		Name:       "Test Credential",
		ID:         "test-id-123",
		Username:   "testuser",
		Password:   "testpass",
		Email:      "test@example.com",
		URL:        "https://example.com",
		CreatedAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		SyncStatus: "synced",
	}

	output, err := formatter.Format(cred)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "Test Credential") {
		t.Errorf("Output does not contain credential name")
	}
	if !strings.Contains(output, "testuser") {
		t.Errorf("Output does not contain username")
	}
}

func TestYAMLFormatter(t *testing.T) {
	formatter := NewYAMLFormatter()

	// Test Format with TextView
	text := &TextView{
		Name:       "Test Note",
		ID:         "note-id-456",
		Content:    "This is a test note",
		Tags:       []string{"tag1", "tag2"},
		CreatedAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		SyncStatus: "pending",
	}

	output, err := formatter.Format(text)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "Test Note") {
		t.Errorf("Output does not contain note name")
	}
	if !strings.Contains(output, "tag1") {
		t.Errorf("Output does not contain tags")
	}
}

func TestTextFormatter(t *testing.T) {
	formatter := NewTextFormatter()

	// Test Format with CardView
	card := &CardView{
		Name:           "Test Card",
		ID:             "card-id-789",
		CardholderName: "John Doe",
		CardNumber:     "1234 5678 9012 3456",
		ExpiryDate:     "12/25",
		CVV:            "123",
		BankName:       "Test Bank",
		CreatedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		SyncStatus:     "synced",
	}

	output, err := formatter.Format(card)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "Test Card") {
		t.Errorf("Output does not contain card name")
	}
	if !strings.Contains(output, "John Doe") {
		t.Errorf("Output does not contain cardholder name")
	}
}

func TestTextFormatterList(t *testing.T) {
	formatter := NewTextFormatter()

	items := []ListItem{
		{
			ID:         "item-1",
			Name:       "Credential 1",
			Type:       pb.SecretType_SECRET_TYPE_CREDENTIAL,
			UpdatedAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			SyncStatus: "synced",
			IsDeleted:  false,
		},
		{
			ID:         "item-2",
			Name:       "Text 1",
			Type:       pb.SecretType_SECRET_TYPE_TEXT,
			UpdatedAt:  time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			SyncStatus: "pending",
			IsDeleted:  false,
		},
	}

	output, err := formatter.FormatList(items)
	if err != nil {
		t.Fatalf("FormatList failed: %v", err)
	}

	if !strings.Contains(output, "Credential 1") {
		t.Errorf("Output does not contain first item")
	}
	if !strings.Contains(output, "Text 1") {
		t.Errorf("Output does not contain second item")
	}
	if !strings.Contains(output, "Items (2)") {
		t.Errorf("Output does not show correct count")
	}
}

func TestTextFormatterEmptyList(t *testing.T) {
	formatter := NewTextFormatter()

	items := []ListItem{}
	output, err := formatter.FormatList(items)
	if err != nil {
		t.Fatalf("FormatList failed: %v", err)
	}

	if !strings.Contains(output, "No items found") {
		t.Errorf("Output does not show 'No items found' message")
	}
}

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		format      string
		expectError bool
	}{
		{"text", false},
		{"json", false},
		{"yaml", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			formatter, err := NewFormatter(tt.format)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for format %s, got none", tt.format)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for format %s, got: %v", tt.format, err)
				}
				if formatter == nil {
					t.Errorf("Expected formatter for format %s, got nil", tt.format)
				}
			}
		})
	}
}

func TestFormatSecretType(t *testing.T) {
	tests := []struct {
		input    pb.SecretType
		expected string
	}{
		{pb.SecretType_SECRET_TYPE_CREDENTIAL, "Credential"},
		{pb.SecretType_SECRET_TYPE_TEXT, "Text"},
		{pb.SecretType_SECRET_TYPE_BANK_CARD, "Card"},
		{pb.SecretType_SECRET_TYPE_BINARY, "Binary"},
		{pb.SecretType_SECRET_TYPE_UNSPECIFIED, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatSecretType(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
