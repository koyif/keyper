package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// NewTextCommands returns the text command group
func NewTextCommands(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	textCmd := &cobra.Command{
		Use:     "text",
		Short:   "Manage text note secrets",
		Long:    "Commands for managing text note secrets (secure notes, memos)",
		Aliases: []string{"note", "notes"},
	}

	textCmd.AddCommand(newTextAddCmd(getCfg, getSess, getStorage))
	textCmd.AddCommand(newTextGetCmd(getCfg, getSess, getStorage))
	textCmd.AddCommand(newTextListCmd(getCfg, getSess, getStorage))
	textCmd.AddCommand(newTextUpdateCmd(getCfg, getSess, getStorage))
	textCmd.AddCommand(newTextDeleteCmd(getCfg, getSess, getStorage))

	return textCmd
}

// newTextAddCmd creates the add text note command
func newTextAddCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var (
		nameFlag    string
		contentFlag string
		tagsFlag    []string
		notesFlag   string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new text note",
		Long:  "Create a new text note with content and optional tags",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			var (
				name, content, notes string
				tags                 []string
			)

			// Use flags if provided, otherwise prompt interactively

			if nameFlag != "" {
				name, content, notes = nameFlag, contentFlag, notesFlag
				tags = tagsFlag
			} else {
				var err error

				name, content, notes, tags, err = promptForTextInput()
				if err != nil {
					return err
				}
			}

			// Create text data
			textData := &pb.TextData{
				Content: content,
			}

			// Marshal text data to JSON
			textJSON, err := protojson.Marshal(textData)
			if err != nil {
				return fmt.Errorf("failed to marshal text data: %w", err)
			}

			// Encrypt the text data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			encryptedData, err := crypto.Encrypt(textJSON, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt text note: %w", err)
			}

			// Create metadata
			metadata := &pb.Metadata{
				Notes: notes,
				Tags:  tags,
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
				Type:           pb.SecretType_SECRET_TYPE_TEXT,
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
			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				if err := repo.Create(ctx, secret); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}

					return fmt.Errorf("failed to store text note: %w", err)
				}

				logrus.Debugf("Text note created: id=%s, name=%s", secret.ID, secret.Name)
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Text note '%s' added successfully\n", name)
				fmt.Fprintf(cmd.OutOrStdout(), "  ID: %s\n", secret.ID)
				fmt.Fprintf(cmd.OutOrStdout(), "  Status: pending sync\n")

				return nil
			})
		},
	}

	// Add flags for non-interactive mode
	cmd.Flags().StringVar(&nameFlag, "name", "", "Note name")
	cmd.Flags().StringVar(&contentFlag, "content", "", "Note content")
	cmd.Flags().StringSliceVar(&tagsFlag, "tags", nil, "Tags (comma-separated)")
	cmd.Flags().StringVar(&notesFlag, "notes", "", "Additional notes")

	return cmd
}

// newTextGetCmd creates the get text note command
func newTextGetCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [name or ID]",
		Short: "Get a text note by name or ID",
		Long:  "Retrieve and decrypt a text note, displaying its contents",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			identifier := args[0]

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Get and validate secret
				secret, err := getSecret(ctx, repo, identifier, pb.SecretType_SECRET_TYPE_TEXT)
				if err != nil {
					return err
				}

				encryptionKey := sess.GetEncryptionKey()
				if encryptionKey == nil {
					return fmt.Errorf("encryption key not found in session")
				}

				decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
				if err != nil {
					return fmt.Errorf("failed to decrypt secret: %w", err)
				}

				// Unmarshal text data
				var textData pb.TextData
				if err := protojson.Unmarshal(decryptedData, &textData); err != nil {
					return fmt.Errorf("failed to unmarshal text data: %w", err)
				}

				// Display text note
				fmt.Fprintf(cmd.OutOrStdout(), "\nText Note: %s\n", secret.Name)
				fmt.Fprintf(cmd.OutOrStdout(), "ID: %s\n", secret.ID)
				fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 80))
				fmt.Fprintln(cmd.OutOrStdout(), textData.Content)
				fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 80))

				// Display metadata if present
				displayTextMetadata(cmd.OutOrStdout(), secret.Metadata)

				fmt.Fprintf(cmd.OutOrStdout(), "\nCreated: %s\n", secret.CreatedAt.Format(time.RFC3339))
				fmt.Fprintf(cmd.OutOrStdout(), "Updated: %s\n", secret.UpdatedAt.Format(time.RFC3339))
				fmt.Fprintf(cmd.OutOrStdout(), "Sync Status: %s\n", secret.SyncStatus)

				return nil
			})
		},
	}

	return cmd
}

// newTextListCmd creates the list text notes command
func newTextListCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var showDeleted bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all text notes",
		Long:    "Display a list of all stored text notes",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				textType := pb.SecretType_SECRET_TYPE_TEXT

				// List text notes
				secrets, err := repo.List(ctx, storage.ListFilters{
					Type:           &textType,
					IncludeDeleted: showDeleted,
				})
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}

					return fmt.Errorf("failed to list text notes: %w", err)
				}

				if len(secrets) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "No text notes found")
					return nil
				}

				// Display text notes
				fmt.Fprintf(cmd.OutOrStdout(), "\nText Notes (%d):\n", len(secrets))
				fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 80))

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

					// Try to get tags from metadata for display
					tags := formatTextTags(secret.Metadata)

					fmt.Fprintf(cmd.OutOrStdout(), "%s %-36s  %s%s\n", status, secret.ID[:8]+"...", secret.Name, tags)
				}

				fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 80))
				fmt.Fprintln(cmd.OutOrStdout(), "✓ synced  ⏳ pending  ⚠ conflict  🗑 deleted")

				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&showDeleted, "deleted", false, "Include deleted text notes")

	return cmd
}

// newTextUpdateCmd creates the update text note command
func newTextUpdateCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [name or ID]",
		Short: "Update an existing text note",
		Long:  "Modify an existing text note's content and metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			identifier := args[0]

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Get and validate secret
				secret, err := getSecret(ctx, repo, identifier, pb.SecretType_SECRET_TYPE_TEXT)
				if err != nil {
					return err
				}

				// Decrypt existing data
				encryptionKey := sess.GetEncryptionKey()
				if encryptionKey == nil {
					return fmt.Errorf("encryption key not found in session")
				}

				decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
				if err != nil {
					return fmt.Errorf("failed to decrypt text note: %w", err)
				}

				var textData pb.TextData
				if err := protojson.Unmarshal(decryptedData, &textData); err != nil {
					return fmt.Errorf("failed to unmarshal text data: %w", err)
				}

				// Prompt for updates
				newName := secret.Name
				newContent := textData.Content

				var metadata pb.Metadata
				if secret.Metadata != "" {
					protojson.Unmarshal([]byte(secret.Metadata), &metadata)
				}

				newNotes := metadata.Notes

				var tagsInput string
				if len(metadata.Tags) > 0 {
					tagsInput = strings.Join(metadata.Tags, ", ")
				}

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

						huh.NewText().
							Title("Content").
							Value(&newContent).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("content is required")
								}

								return nil
							}),

						huh.NewInput().
							Title("Tags").
							Description("Comma-separated tags").
							Value(&tagsInput),

						huh.NewInput().
							Title("Notes").
							Value(&newNotes),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("operation cancelled: %w", err)
				}

				// Update text data
				textData.Content = newContent

				// Marshal and encrypt
				textJSON, err := protojson.Marshal(&textData)
				if err != nil {
					return fmt.Errorf("failed to marshal text data: %w", err)
				}

				encryptedData, err := crypto.Encrypt(textJSON, encryptionKey)
				if err != nil {
					return fmt.Errorf("failed to encrypt text note: %w", err)
				}

				// Update metadata
				metadata.Notes = newNotes
				// Parse tags
				metadata.Tags = nil

				if tagsInput != "" {
					for _, tag := range strings.Split(tagsInput, ",") {
						tag = strings.TrimSpace(tag)
						if tag != "" {
							metadata.Tags = append(metadata.Tags, tag)
						}
					}
				}

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
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}

					return fmt.Errorf("failed to update text note: %w", err)
				}

				logrus.Debugf("Text note updated: id=%s, name=%s", secret.ID, secret.Name)
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Text note '%s' updated successfully\n", newName)
				fmt.Fprintf(cmd.OutOrStdout(), "  Status: pending sync\n")

				return nil
			})
		},
	}

	return cmd
}

// newTextDeleteCmd creates the delete text note command
func newTextDeleteCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var noConfirm bool

	cmd := &cobra.Command{
		Use:     "delete [name or ID]",
		Short:   "Delete a text note",
		Long:    "Soft-delete a text note (marks as deleted, will sync to server)",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			identifier := args[0]

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Get and validate secret
				secret, err := getSecret(ctx, repo, identifier, pb.SecretType_SECRET_TYPE_TEXT)
				if err != nil {
					return err
				}

				// Confirm deletion
				confirm, err := confirmDeletion(secret.Name, "text note", noConfirm)
				if err != nil {
					return err
				}

				if !confirm {
					fmt.Fprintln(cmd.OutOrStdout(), "Deletion cancelled")
					return nil
				}

				// Delete (soft delete)
				if err := repo.Delete(ctx, secret.ID); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}

					return fmt.Errorf("failed to delete text note: %w", err)
				}

				logrus.Debugf("Text note deleted: id=%s, name=%s", secret.ID, secret.Name)
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Text note '%s' deleted successfully\n", secret.Name)
				fmt.Fprintf(cmd.OutOrStdout(), "  Status: pending sync\n")

				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&noConfirm, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}

// displayTextMetadata displays metadata fields (tags and notes) if present
func displayTextMetadata(w interface {
	Write(p []byte) (n int, err error)
}, metadataJSON string) {
	if metadataJSON == "" {
		return
	}

	var metadata pb.Metadata
	if err := protojson.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return
	}

	if len(metadata.Tags) > 0 {
		fmt.Fprintf(w, "Tags: %s\n", strings.Join(metadata.Tags, ", "))
	}

	if metadata.Notes != "" {
		fmt.Fprintf(w, "Notes: %s\n", metadata.Notes)
	}
}

// formatTextTags extracts and formats text tags for display
func formatTextTags(metadata string) string {
	if metadata == "" {
		return ""
	}

	var md pb.Metadata
	if err := protojson.Unmarshal([]byte(metadata), &md); err != nil {
		return ""
	}

	if len(md.Tags) == 0 {
		return ""
	}

	return " [" + strings.Join(md.Tags, ", ") + "]"
}

// promptForTextInput prompts user for text note details interactively
func promptForTextInput() (name, content, notes string, tags []string, err error) {
	var tagsInput string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Name").
				Description("A friendly name for this note (e.g., 'Meeting Notes')").
				Value(&name).
				Validate(func(s string) error {
					if len(s) == 0 {
						return fmt.Errorf("name is required")
					}

					return nil
				}),

			huh.NewText().
				Title("Content").
				Description("The text content of your note").
				Value(&content).
				Validate(func(s string) error {
					if len(s) == 0 {
						return fmt.Errorf("content is required")
					}

					return nil
				}),

			huh.NewInput().
				Title("Tags (optional)").
				Description("Comma-separated tags (e.g., 'work, important')").
				Value(&tagsInput),

			huh.NewInput().
				Title("Notes (optional)").
				Description("Additional notes or metadata").
				Value(&notes),
		),
	)

	if err = form.Run(); err != nil {
		return "", "", "", nil, fmt.Errorf("operation cancelled: %w", err)
	}

	// Parse tags
	if tagsInput != "" {
		for _, tag := range strings.Split(tagsInput, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	return name, content, notes, tags, nil
}
