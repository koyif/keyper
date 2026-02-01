package output

import (
	"fmt"
	"time"

	"github.com/koyif/keyper/internal/client/storage"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// FormatSecret formats a LocalSecret for display
func FormatSecret(secret *storage.LocalSecret, decryptedData []byte, format string) (string, error) {
	formatter, err := NewFormatter(format)
	if err != nil {
		return "", err
	}

	// Convert to appropriate view type based on secret type
	var view interface{}

	switch secret.Type {
	case pb.SecretType_SECRET_TYPE_CREDENTIAL:
		var credData pb.CredentialData
		if err := protojson.Unmarshal(decryptedData, &credData); err != nil {
			return "", fmt.Errorf("failed to unmarshal credential data: %w", err)
		}

		// Parse metadata if present
		var notes string

		if secret.Metadata != "" {
			var metadata pb.Metadata
			if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
				notes = metadata.Notes
			}
		}

		view = &CredentialView{
			Name:       secret.Name,
			ID:         secret.ID,
			Username:   credData.Username,
			Password:   credData.Password,
			Email:      credData.Email,
			URL:        credData.Url,
			Notes:      notes,
			CreatedAt:  secret.CreatedAt,
			UpdatedAt:  secret.UpdatedAt,
			SyncStatus: string(secret.SyncStatus),
		}

	case pb.SecretType_SECRET_TYPE_TEXT:
		var textData pb.TextData
		if err := protojson.Unmarshal(decryptedData, &textData); err != nil {
			return "", fmt.Errorf("failed to unmarshal text data: %w", err)
		}

		// Parse metadata if present
		var (
			notes string
			tags  []string
		)

		if secret.Metadata != "" {
			var metadata pb.Metadata
			if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
				notes = metadata.Notes
				tags = metadata.Tags
			}
		}

		view = &TextView{
			Name:       secret.Name,
			ID:         secret.ID,
			Content:    textData.Content,
			Tags:       tags,
			Notes:      notes,
			CreatedAt:  secret.CreatedAt,
			UpdatedAt:  secret.UpdatedAt,
			SyncStatus: string(secret.SyncStatus),
		}

	case pb.SecretType_SECRET_TYPE_BANK_CARD:
		var cardData pb.BankCardData
		if err := protojson.Unmarshal(decryptedData, &cardData); err != nil {
			return "", fmt.Errorf("failed to unmarshal card data: %w", err)
		}

		// Parse metadata if present
		var notes string

		if secret.Metadata != "" {
			var metadata pb.Metadata
			if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
				notes = metadata.Notes
			}
		}

		// Combine expiry month and year
		expiryDate := fmt.Sprintf("%s/%s", cardData.ExpiryMonth, cardData.ExpiryYear)

		view = &CardView{
			Name:           secret.Name,
			ID:             secret.ID,
			CardholderName: cardData.CardholderName,
			CardNumber:     cardData.CardNumber,
			ExpiryDate:     expiryDate,
			CVV:            cardData.Cvv,
			PIN:            cardData.Pin,
			BankName:       cardData.BankName,
			Notes:          notes,
			CreatedAt:      secret.CreatedAt,
			UpdatedAt:      secret.UpdatedAt,
			SyncStatus:     string(secret.SyncStatus),
		}

	case pb.SecretType_SECRET_TYPE_BINARY:
		var binaryData pb.BinaryData
		if err := protojson.Unmarshal(decryptedData, &binaryData); err != nil {
			return "", fmt.Errorf("failed to unmarshal binary data: %w", err)
		}

		// Parse metadata if present
		var notes string

		if secret.Metadata != "" {
			var metadata pb.Metadata
			if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
				notes = metadata.Notes
			}
		}

		view = &BinaryView{
			Name:       secret.Name,
			ID:         secret.ID,
			Filename:   binaryData.Filename,
			MimeType:   binaryData.MimeType,
			Size:       int64(len(binaryData.Data)),
			Notes:      notes,
			CreatedAt:  secret.CreatedAt,
			UpdatedAt:  secret.UpdatedAt,
			SyncStatus: string(secret.SyncStatus),
		}

	default:
		return "", fmt.Errorf("unsupported secret type: %v", secret.Type)
	}

	output, err := formatter.Format(view)
	if err != nil {
		return "", fmt.Errorf("failed to format secret: %w", err)
	}

	return output, nil
}

// FormatSecretList formats a list of secrets for display
func FormatSecretList(secrets []*storage.LocalSecret, format string) (string, error) {
	formatter, err := NewFormatter(format)
	if err != nil {
		return "", err
	}

	// Convert to list items
	items := make([]ListItem, len(secrets))
	for i, secret := range secrets {
		items[i] = ListItem{
			ID:         secret.ID,
			Name:       secret.Name,
			Type:       secret.Type,
			UpdatedAt:  secret.UpdatedAt,
			SyncStatus: string(secret.SyncStatus),
			IsDeleted:  secret.IsDeleted,
		}
	}

	output, err := formatter.FormatList(items)
	if err != nil {
		return "", fmt.Errorf("failed to format secret list: %w", err)
	}

	return output, nil
}

// FormatError formats an error message
func FormatError(err error) string {
	return fmt.Sprintf("Error: %v\n", err)
}

// FormatSuccess formats a success message
func FormatSuccess(message string) string {
	return fmt.Sprintf("%s\n", message)
}

// ConvertSecretToMap converts a LocalSecret to a map for JSON/YAML output
func ConvertSecretToMap(secret *storage.LocalSecret, decryptedData []byte) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"id":          secret.ID,
		"name":        secret.Name,
		"type":        formatSecretType(secret.Type),
		"created_at":  secret.CreatedAt.Format(time.RFC3339),
		"updated_at":  secret.UpdatedAt.Format(time.RFC3339),
		"sync_status": secret.SyncStatus,
		"is_deleted":  secret.IsDeleted,
	}

	// Add decrypted data based on type
	switch secret.Type {
	case pb.SecretType_SECRET_TYPE_CREDENTIAL:
		var credData pb.CredentialData
		if err := protojson.Unmarshal(decryptedData, &credData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential data: %w", err)
		}

		result["username"] = credData.Username
		result["password"] = credData.Password
		result["email"] = credData.Email
		result["url"] = credData.Url

	case pb.SecretType_SECRET_TYPE_TEXT:
		var textData pb.TextData
		if err := protojson.Unmarshal(decryptedData, &textData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal text data: %w", err)
		}

		result["content"] = textData.Content

	case pb.SecretType_SECRET_TYPE_BANK_CARD:
		var cardData pb.BankCardData
		if err := protojson.Unmarshal(decryptedData, &cardData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal card data: %w", err)
		}

		result["cardholder_name"] = cardData.CardholderName
		result["card_number"] = cardData.CardNumber
		result["expiry_month"] = cardData.ExpiryMonth
		result["expiry_year"] = cardData.ExpiryYear
		result["cvv"] = cardData.Cvv
		result["pin"] = cardData.Pin
		result["bank_name"] = cardData.BankName

	case pb.SecretType_SECRET_TYPE_BINARY:
		var binaryData pb.BinaryData
		if err := protojson.Unmarshal(decryptedData, &binaryData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal binary data: %w", err)
		}

		result["filename"] = binaryData.Filename
		result["mime_type"] = binaryData.MimeType
		result["size"] = len(binaryData.Data)
	}

	// Add metadata if present
	addMetadataToMap(secret.Metadata, result)

	return result, nil
}

// addMetadataToMap adds metadata fields to the result map if present
func addMetadataToMap(metadataJSON string, result map[string]interface{}) {
	if metadataJSON == "" {
		return
	}

	var metadata pb.Metadata
	if err := protojson.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return
	}

	if metadata.Notes != "" {
		result["notes"] = metadata.Notes
	}

	if len(metadata.Tags) > 0 {
		result["metadata_tags"] = metadata.Tags
	}
}
