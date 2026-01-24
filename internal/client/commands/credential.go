package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/google/uuid"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// NewCredentialCommands returns the credential command group
func NewCredentialCommands(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	credCmd := &cobra.Command{
		Use:     "credential",
		Short:   "Manage credential secrets",
		Long:    "Commands for managing credential secrets (username/password pairs)",
		Aliases: []string{"cred", "credentials"},
	}

	credCmd.AddCommand(newCredentialAddCmd(getCfg, getSess, getStorage))
	credCmd.AddCommand(newCredentialGetCmd(getCfg, getSess, getStorage))
	credCmd.AddCommand(newCredentialListCmd(getCfg, getSess, getStorage))
	credCmd.AddCommand(newCredentialUpdateCmd(getCfg, getSess, getStorage))
	credCmd.AddCommand(newCredentialDeleteCmd(getCfg, getSess, getStorage))

	return credCmd
}

// newCredentialAddCmd creates the add credential command
func newCredentialAddCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var (
		nameFlag     string
		usernameFlag string
		passwordFlag string
		emailFlag    string
		urlFlag      string
		notesFlag    string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new credential",
		Long:  "Create a new credential with username, password, and optional metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			var name, username, password, email, url, notes string

			// Use flags if provided, otherwise prompt interactively
			if nameFlag != "" {
				name = nameFlag
				username = usernameFlag
				password = passwordFlag
				email = emailFlag
				url = urlFlag
				notes = notesFlag
			} else {
				// Interactive prompts
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().
							Title("Name").
							Description("A friendly name for this credential (e.g., 'GitHub Account')").
							Value(&name).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("name is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("Username").
							Description("Username or account identifier").
							Value(&username).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("username is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("Password").
							Description("Password for this account").
							Value(&password).
							EchoMode(huh.EchoModePassword).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("password is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("Email (optional)").
							Value(&email),

						huh.NewInput().
							Title("URL (optional)").
							Description("Website or service URL").
							Value(&url),

						huh.NewInput().
							Title("Notes (optional)").
							Description("Additional notes or comments").
							Value(&notes),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("operation cancelled: %w", err)
				}
			}

			// Create credential data
			credData := &pb.CredentialData{
				Username: username,
				Password: password,
				Email:    email,
				Url:      url,
			}

			// Marshal credential data to JSON
			credJSON, err := protojson.Marshal(credData)
			if err != nil {
				return fmt.Errorf("failed to marshal credential data: %w", err)
			}

			// Encrypt the credential data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			encryptedData, err := crypto.Encrypt(credJSON, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt credential: %w", err)
			}

			// Create metadata
			metadata := &pb.Metadata{
				Notes: notes,
				Url:   url,
			}
			metadataJSON, err := protojson.Marshal(metadata)
			if err != nil {
				return fmt.Errorf("failed to marshal metadata: %w", err)
			}

			// Create local secret
			now := time.Now()
			secret := &storage.LocalSecret{
				ID:             uuid.New().String(),
				Name:           name,
				Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData:  []byte(encryptedData),
				Nonce:          []byte{}, // Nonce is embedded in encrypted data by crypto.Encrypt
				Metadata:       string(metadataJSON),
				Version:        1,
				IsDeleted:      false,
				SyncStatus:     storage.SyncStatusPending,
				ServerVersion:  0,
				CreatedAt:      now,
				UpdatedAt:      now,
				LocalUpdatedAt: now,
			}

			// Store in database
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()
			if err := repo.Create(ctx, secret); err != nil {
				return fmt.Errorf("failed to store credential: %w", err)
			}

			logrus.Debugf("Credential created: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Credential '%s' added successfully\n", name)
			fmt.Printf("  ID: %s\n", secret.ID)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	// Add flags for non-interactive mode
	cmd.Flags().StringVar(&nameFlag, "name", "", "Credential name")
	cmd.Flags().StringVar(&usernameFlag, "username", "", "Username")
	cmd.Flags().StringVar(&passwordFlag, "password", "", "Password")
	cmd.Flags().StringVar(&emailFlag, "email", "", "Email address")
	cmd.Flags().StringVar(&urlFlag, "url", "", "URL")
	cmd.Flags().StringVar(&notesFlag, "notes", "", "Additional notes")

	return cmd
}

// newCredentialGetCmd creates the get credential command
func newCredentialGetCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [name or ID]",
		Short: "Get a credential by name or ID",
		Long:  "Retrieve and decrypt a credential, displaying its details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			identifier := args[0]

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()

			// Try to get by ID first, then by name
			var secret *storage.LocalSecret
			secret, err = repo.Get(ctx, identifier)
			if err != nil {
				// Try by name
				secret, err = repo.GetByName(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %s", identifier)
				}
			}

			// Check if deleted
			if secret.IsDeleted {
				return fmt.Errorf("credential has been deleted")
			}

			// Check type
			if secret.Type != pb.SecretType_SECRET_TYPE_CREDENTIAL {
				return fmt.Errorf("secret is not a credential (type: %s)", secret.Type)
			}

			// Decrypt the data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt credential: %w", err)
			}

			// Unmarshal credential data
			var credData pb.CredentialData
			if err := protojson.Unmarshal(decryptedData, &credData); err != nil {
				return fmt.Errorf("failed to unmarshal credential data: %w", err)
			}

			// Display credential
			fmt.Printf("\nCredential: %s\n", secret.Name)
			fmt.Printf("ID: %s\n", secret.ID)
			fmt.Printf("Username: %s\n", credData.Username)
			fmt.Printf("Password: %s\n", credData.Password)
			if credData.Email != "" {
				fmt.Printf("Email: %s\n", credData.Email)
			}
			if credData.Url != "" {
				fmt.Printf("URL: %s\n", credData.Url)
			}

			// Display metadata if present
			if secret.Metadata != "" {
				var metadata pb.Metadata
				if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
					if metadata.Notes != "" {
						fmt.Printf("Notes: %s\n", metadata.Notes)
					}
				}
			}

			fmt.Printf("\nCreated: %s\n", secret.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format(time.RFC3339))
			fmt.Printf("Sync Status: %s\n", secret.SyncStatus)

			return nil
		},
	}

	return cmd
}

// newCredentialListCmd creates the list credentials command
func newCredentialListCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var showDeleted bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all credentials",
		Long:    "Display a list of all stored credentials",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()
			credType := pb.SecretType_SECRET_TYPE_CREDENTIAL

			// List credentials
			secrets, err := repo.List(ctx, storage.ListFilters{
				Type:           &credType,
				IncludeDeleted: showDeleted,
			})
			if err != nil {
				return fmt.Errorf("failed to list credentials: %w", err)
			}

			if len(secrets) == 0 {
				fmt.Println("No credentials found")
				return nil
			}

			// Display credentials
			fmt.Printf("\nCredentials (%d):\n", len(secrets))
			fmt.Println(strings.Repeat("-", 80))

			for _, secret := range secrets {
				status := "✓"
				if secret.SyncStatus == storage.SyncStatusPending {
					status = "⏳"
				} else if secret.SyncStatus == storage.SyncStatusConflict {
					status = "⚠"
				}
				if secret.IsDeleted {
					status = "🗑"
				}

				// Try to get URL from metadata for display
				url := ""
				if secret.Metadata != "" {
					var metadata pb.Metadata
					if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
						url = metadata.Url
					}
				}

				fmt.Printf("%s %-36s  %s", status, secret.ID[:8]+"...", secret.Name)
				if url != "" {
					fmt.Printf("  (%s)", url)
				}
				fmt.Println()
			}

			fmt.Println(strings.Repeat("-", 80))
			fmt.Println("✓ synced  ⏳ pending  ⚠ conflict  🗑 deleted")

			return nil
		},
	}

	cmd.Flags().BoolVar(&showDeleted, "deleted", false, "Include deleted credentials")

	return cmd
}

// newCredentialUpdateCmd creates the update credential command
func newCredentialUpdateCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [name or ID]",
		Short: "Update an existing credential",
		Long:  "Modify an existing credential's fields",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			identifier := args[0]

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()

			// Get existing secret
			var secret *storage.LocalSecret
			secret, err = repo.Get(ctx, identifier)
			if err != nil {
				secret, err = repo.GetByName(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %s", identifier)
				}
			}

			if secret.IsDeleted {
				return fmt.Errorf("credential has been deleted")
			}

			if secret.Type != pb.SecretType_SECRET_TYPE_CREDENTIAL {
				return fmt.Errorf("secret is not a credential")
			}

			// Decrypt existing data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt credential: %w", err)
			}

			var credData pb.CredentialData
			if err := protojson.Unmarshal(decryptedData, &credData); err != nil {
				return fmt.Errorf("failed to unmarshal credential data: %w", err)
			}

			// Prompt for updates
			newName := secret.Name
			newUsername := credData.Username
			newPassword := credData.Password
			newEmail := credData.Email
			newUrl := credData.Url

			var metadata pb.Metadata
			if secret.Metadata != "" {
				protojson.Unmarshal([]byte(secret.Metadata), &metadata)
			}
			newNotes := metadata.Notes

			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().
						Title("Name").
						Value(&newName).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("name is required")
							}
							return nil
						}),

					huh.NewInput().
						Title("Username").
						Value(&newUsername).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("username is required")
							}
							return nil
						}),

					huh.NewInput().
						Title("Password").
						Value(&newPassword).
						EchoMode(huh.EchoModePassword),

					huh.NewInput().
						Title("Email").
						Value(&newEmail),

					huh.NewInput().
						Title("URL").
						Value(&newUrl),

					huh.NewInput().
						Title("Notes").
						Value(&newNotes),
				),
			)

			if err := form.Run(); err != nil {
				return fmt.Errorf("operation cancelled: %w", err)
			}

			// Update credential data
			credData.Username = newUsername
			credData.Password = newPassword
			credData.Email = newEmail
			credData.Url = newUrl

			// Marshal and encrypt
			credJSON, err := protojson.Marshal(&credData)
			if err != nil {
				return fmt.Errorf("failed to marshal credential data: %w", err)
			}

			encryptedData, err := crypto.Encrypt(credJSON, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt credential: %w", err)
			}

			// Update metadata
			metadata.Notes = newNotes
			metadata.Url = newUrl
			metadataJSON, err := protojson.Marshal(&metadata)
			if err != nil {
				return fmt.Errorf("failed to marshal metadata: %w", err)
			}

			// Update secret
			secret.Name = newName
			secret.EncryptedData = []byte(encryptedData)
			secret.Nonce = []byte{} // Nonce is embedded in encrypted data
			secret.Metadata = string(metadataJSON)
			secret.Version++
			secret.SyncStatus = storage.SyncStatusPending
			secret.UpdatedAt = time.Now()
			secret.LocalUpdatedAt = time.Now()

			if err := repo.Update(ctx, secret); err != nil {
				return fmt.Errorf("failed to update credential: %w", err)
			}

			logrus.Debugf("Credential updated: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Credential '%s' updated successfully\n", newName)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	return cmd
}

// newCredentialDeleteCmd creates the delete credential command
func newCredentialDeleteCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var noConfirm bool

	cmd := &cobra.Command{
		Use:     "delete [name or ID]",
		Short:   "Delete a credential",
		Long:    "Soft-delete a credential (marks as deleted, will sync to server)",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			identifier := args[0]

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()

			// Get secret to confirm
			var secret *storage.LocalSecret
			secret, err = repo.Get(ctx, identifier)
			if err != nil {
				secret, err = repo.GetByName(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %s", identifier)
				}
			}

			if secret.IsDeleted {
				return fmt.Errorf("credential already deleted")
			}

			if secret.Type != pb.SecretType_SECRET_TYPE_CREDENTIAL {
				return fmt.Errorf("secret is not a credential")
			}

			// Confirm deletion
			if !noConfirm {
				var confirm bool
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title(fmt.Sprintf("Delete credential '%s'?", secret.Name)).
							Description("This will mark the credential as deleted and sync to the server.").
							Value(&confirm),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("operation cancelled: %w", err)
				}

				if !confirm {
					fmt.Println("Deletion cancelled")
					return nil
				}
			}

			// Delete (soft delete)
			if err := repo.Delete(ctx, secret.ID); err != nil {
				return fmt.Errorf("failed to delete credential: %w", err)
			}

			logrus.Debugf("Credential deleted: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Credential '%s' deleted successfully\n", secret.Name)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&noConfirm, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}
