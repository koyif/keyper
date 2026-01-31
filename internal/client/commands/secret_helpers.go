package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// getSecret retrieves a secret by ID or name with type validation.
func getSecret(ctx context.Context, repo storage.Repository, identifier string, expectedType pb.SecretType) (*storage.LocalSecret, error) {
	var secret *storage.LocalSecret
	secret, err := repo.Get(ctx, identifier)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("database operation timed out after 30s")
		}
		secret, err = repo.GetByName(ctx, identifier)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("database operation timed out after 30s")
			}
			return nil, fmt.Errorf("secret not found: %s", identifier)
		}
	}

	if secret.IsDeleted {
		return nil, fmt.Errorf("secret has been deleted")
	}

	if secret.Type != expectedType {
		return nil, fmt.Errorf("secret is not of expected type %s (found: %s)", expectedType, secret.Type)
	}

	return secret, nil
}

// confirmDeletion prompts the user to confirm deletion of a secret.
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

// withStorage is a helper function that handles the boilerplate of opening storage,
// creating a context, and ensuring proper cleanup via defer statements.
// It opens the storage repository, creates a database context with timeout,
// and ensures both are properly closed/cancelled when the function completes.
func withStorage(getStorage func() (storage.Repository, error), fn func(context.Context, storage.Repository) error) error {
	repo, err := getStorage()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer repo.Close()

	ctx, cancel := session.DatabaseContext()
	defer cancel()

	return fn(ctx, repo)
}
