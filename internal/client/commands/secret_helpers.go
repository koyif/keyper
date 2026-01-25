package commands

import (
	"context"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// getSecret retrieves a secret by ID or name with type validation.
// This helper consolidates the common pattern of:
// 1. Try to get by ID
// 2. If that fails, try by name
// 3. Validate the secret is not deleted
// 4. Validate the secret type matches expected type
func getSecret(ctx context.Context, repo storage.Repository, identifier string, expectedType pb.SecretType) (*storage.LocalSecret, error) {
	// Try to get by ID first, then by name
	var secret *storage.LocalSecret
	secret, err := repo.Get(ctx, identifier)
	if err != nil {
		// Try by name
		secret, err = repo.GetByName(ctx, identifier)
		if err != nil {
			return nil, fmt.Errorf("secret not found: %s", identifier)
		}
	}

	// Check if deleted
	if secret.IsDeleted {
		return nil, fmt.Errorf("secret has been deleted")
	}

	// Check type
	if secret.Type != expectedType {
		return nil, fmt.Errorf("secret is not of expected type %s (found: %s)", expectedType, secret.Type)
	}

	return secret, nil
}

// decryptSecret decrypts a secret's encrypted data using the session's encryption key.
// This helper consolidates the common pattern of:
// 1. Retrieving the encryption key from session
// 2. Validating the key exists
// 3. Decrypting the data
func decryptSecret(secret *storage.LocalSecret, sess *session.Session) ([]byte, error) {
	encryptionKey := sess.GetEncryptionKey()
	if encryptionKey == nil {
		return nil, fmt.Errorf("encryption key not found in session")
	}

	decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return decryptedData, nil
}

// confirmDeletion prompts the user to confirm deletion of a secret.
// This helper consolidates the common deletion confirmation pattern.
// If noConfirm is true, it skips the confirmation prompt.
// Returns true if deletion should proceed, false if cancelled.
func confirmDeletion(secretName string, secretType string, noConfirm bool) (bool, error) {
	if noConfirm {
		return true, nil
	}

	var confirm bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Delete %s '%s'?", secretType, secretName)).
				Description(fmt.Sprintf("This will mark the %s as deleted and sync to the server.", secretType)).
				Value(&confirm),
		),
	)

	if err := form.Run(); err != nil {
		return false, fmt.Errorf("operation cancelled: %w", err)
	}

	return confirm, nil
}
