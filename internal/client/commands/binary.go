//nolint:forbidigo // CLI command requires user output via fmt.Print* for progress and results
package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

const (
	// MaxFileSize is the recommended maximum file size (10MB)
	MaxFileSize = 10 * 1024 * 1024
	// ChunkSize for reading large files
	ChunkSize = 64 * 1024
)

// NewBinaryCommands returns the binary command group
func NewBinaryCommands(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	binCmd := &cobra.Command{
		Use:     "binary",
		Short:   "Manage binary secrets",
		Long:    "Commands for managing binary secrets (files, images, documents, etc.)",
		Aliases: []string{"file", "files"},
	}

	binCmd.AddCommand(newBinaryAddCmd(getCfg, getSess, getStorage))
	binCmd.AddCommand(newBinaryGetCmd(getCfg, getSess, getStorage))
	binCmd.AddCommand(newBinaryListCmd(getCfg, getSess, getStorage))
	binCmd.AddCommand(newBinaryDeleteCmd(getCfg, getSess, getStorage))

	return binCmd
}

// newBinaryAddCmd creates the add binary command
func newBinaryAddCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var (
		nameFlag  string
		fileFlag  string
		notesFlag string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new binary secret",
		Long:  "Upload a file as an encrypted binary secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			var name, filePath, notes string

			// Use flags if provided, otherwise prompt interactively
			if fileFlag != "" {
				name = nameFlag
				filePath = fileFlag
				notes = notesFlag
			} else {
				// Interactive prompts
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().
							Title("Name").
							Description("A friendly name for this file").
							Value(&name).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("name is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("File Path").
							Description("Path to the file to upload").
							Value(&filePath).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("file path is required")
								}
								// Clean and validate the path
								cleaned := filepath.Clean(s)
								if _, err := os.Stat(cleaned); err != nil {
									return fmt.Errorf("file not found: %s", cleaned)
								}
								return nil
							}),

						huh.NewInput().
							Title("Notes (optional)").
							Description("Additional notes about this file").
							Value(&notes),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("operation cancelled: %w", err)
				}
			}

			// Clean the file path to prevent path traversal
			filePath = filepath.Clean(filePath)

			// Open and read the file
			file, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer file.Close()

			// Get file info
			fileInfo, err := file.Stat()
			if err != nil {
				return fmt.Errorf("failed to get file info: %w", err)
			}

			fileSize := fileInfo.Size()

			// Warn if file is large
			if fileSize > MaxFileSize {
				fmt.Printf("⚠ Warning: File size is %.2f MB (larger than recommended 10 MB)\n", float64(fileSize)/(1024*1024))

				var proceed bool
				confirmForm := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title("Continue with upload?").
							Value(&proceed),
					),
				)

				if err := confirmForm.Run(); err != nil || !proceed {
					return fmt.Errorf("upload cancelled")
				}
			}

			// Read file data with progress for large files
			var fileData []byte
			if fileSize > ChunkSize {
				fmt.Printf("Reading file (%.2f MB)...\n", float64(fileSize)/(1024*1024))
				fileData = make([]byte, fileSize)
				var totalRead int64
				for {
					n, err := file.Read(fileData[totalRead:])
					totalRead += int64(n)

					if err == io.EOF {
						break
					}
					if err != nil {
						return fmt.Errorf("failed to read file: %w", err)
					}

					// Show progress
					progress := float64(totalRead) / float64(fileSize) * 100
					fmt.Printf("\rProgress: %.1f%%", progress)
				}
				fmt.Println()
			} else {
				fileData, err = io.ReadAll(file)
				if err != nil {
					return fmt.Errorf("failed to read file: %w", err)
				}
			}

			// Detect MIME type
			mimeType := http.DetectContentType(fileData)

			// Get original filename
			filename := filepath.Base(filePath)

			// Create binary data
			binaryData := &pb.BinaryData{
				Filename: filename,
				MimeType: mimeType,
				Size:     fileSize,
				Data:     fileData,
			}

			// Marshal binary data to protobuf
			binaryBytes, err := protojson.Marshal(binaryData)
			if err != nil {
				return fmt.Errorf("failed to marshal binary data: %w", err)
			}

			// Encrypt the binary data
			fmt.Println("Encrypting file...")
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			encryptedData, err := crypto.Encrypt(binaryBytes, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt file: %w", err)
			}

			// Create metadata
			metadata := &pb.Metadata{
				Notes: notes,
				CustomFields: map[string]string{
					"original_filename": filename,
					"mime_type":         mimeType,
					"file_size":         fmt.Sprintf("%d", fileSize),
				},
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
				Type:           pb.SecretType_SECRET_TYPE_BINARY,
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
					return fmt.Errorf("failed to store binary secret: %w", err)
				}

				logrus.Debugf("Binary secret created: id=%s, name=%s, size=%d", secret.ID, secret.Name, fileSize)
				fmt.Printf("✓ Binary secret '%s' added successfully\n", name)
				fmt.Printf("  ID: %s\n", secret.ID)
				fmt.Printf("  File: %s\n", filename)
				fmt.Printf("  Size: %.2f MB\n", float64(fileSize)/(1024*1024))
				fmt.Printf("  Type: %s\n", mimeType)
				fmt.Printf("  Status: pending sync\n")

				return nil
			})
		},
	}

	// Add flags for non-interactive mode
	cmd.Flags().StringVar(&nameFlag, "name", "", "Binary secret name")
	cmd.Flags().StringVar(&fileFlag, "file", "", "Path to file to upload")
	cmd.Flags().StringVar(&notesFlag, "notes", "", "Additional notes")

	return cmd
}

// newBinaryGetCmd creates the get binary command
func newBinaryGetCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "get [name or ID]",
		Short: "Get a binary secret by name or ID",
		Long:  "Retrieve and decrypt a binary secret, downloading the file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			identifier := args[0]

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Try to get by ID first, then by name
				var secret *storage.LocalSecret
				secret, err := repo.Get(ctx, identifier)
				if err != nil {
					// Try by name
					secret, err = repo.GetByName(ctx, identifier)
					if err != nil {
						return fmt.Errorf("binary secret not found: %s", identifier)
					}
				}

				// Check if deleted
				if secret.IsDeleted {
					return fmt.Errorf("binary secret has been deleted")
				}

				// Check type
				if secret.Type != pb.SecretType_SECRET_TYPE_BINARY {
					return fmt.Errorf("secret is not a binary file (type: %s)", secret.Type)
				}

				// Decrypt the data
				fmt.Println("Decrypting file...")
				encryptionKey := sess.GetEncryptionKey()
				if encryptionKey == nil {
					return fmt.Errorf("encryption key not found in session")
				}

				decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
				if err != nil {
					return fmt.Errorf("failed to decrypt binary secret: %w", err)
				}

				// Unmarshal binary data
				var binaryData pb.BinaryData
				if err := protojson.Unmarshal(decryptedData, &binaryData); err != nil {
					return fmt.Errorf("failed to unmarshal binary data: %w", err)
				}

				// Determine output path
				var finalOutputPath string
				if outputPath != "" {
					// Use specified output path
					finalOutputPath = filepath.Clean(outputPath)
				} else if cmd.Flags().Changed("output") && outputPath == "" {
					// If --output was specified but empty, write to stdout
					_, err := os.Stdout.Write(binaryData.Data)
					if err != nil {
						return fmt.Errorf("failed to write to stdout: %w", err)
					}
					return nil
				} else {
					// Use original filename in current directory
					finalOutputPath = filepath.Clean(binaryData.Filename)
				}

				// Check if file exists
				if _, err := os.Stat(finalOutputPath); err == nil {
					var overwrite bool
					form := huh.NewForm(
						huh.NewGroup(
							huh.NewConfirm().
								Title(fmt.Sprintf("File '%s' already exists. Overwrite?", finalOutputPath)).
								Value(&overwrite),
						),
					)

					if err := form.Run(); err != nil || !overwrite {
						return fmt.Errorf("download cancelled")
					}
				}

				// Write file
				fmt.Printf("Writing file to %s...\n", finalOutputPath)
				if err := os.WriteFile(finalOutputPath, binaryData.Data, 0600); err != nil {
					return fmt.Errorf("failed to write file: %w", err)
				}

				// Display info
				fmt.Printf("\n✓ Binary secret '%s' downloaded successfully\n", secret.Name)
				fmt.Printf("  File: %s\n", finalOutputPath)
				fmt.Printf("  Size: %.2f MB\n", float64(binaryData.Size)/(1024*1024))
				fmt.Printf("  Type: %s\n", binaryData.MimeType)

				return nil
			})
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (omit for original filename, use empty string for stdout)")

	return cmd
}

// newBinaryListCmd creates the list binary secrets command
func newBinaryListCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var showDeleted bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all binary secrets",
		Long:    "Display a list of all stored binary secrets",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				binType := pb.SecretType_SECRET_TYPE_BINARY

				// List binary secrets
				secrets, err := repo.List(ctx, storage.ListFilters{
					Type:           &binType,
					IncludeDeleted: showDeleted,
				})
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}
					return fmt.Errorf("failed to list binary secrets: %w", err)
				}

				if len(secrets) == 0 {
					fmt.Println("No binary secrets found")
					return nil
				}

				// Display binary secrets
				fmt.Printf("\nBinary Secrets (%d):\n", len(secrets))
				fmt.Println(strings.Repeat("-", 100))
				fmt.Printf("%-10s %-30s %-30s %-15s %s\n", "Status", "ID", "Name", "Size", "Type")
				fmt.Println(strings.Repeat("-", 100))

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

					// Try to get file info from metadata
					mimeType := ""
					fileSize := ""
					if secret.Metadata != "" {
						var metadata pb.Metadata
						if err := protojson.Unmarshal([]byte(secret.Metadata), &metadata); err == nil {
							if metadata.CustomFields != nil {
								mimeType = metadata.CustomFields["mime_type"]
								fileSize = metadata.CustomFields["file_size"]
							}
						}
					}

					// Format size
					if fileSize != "" {
						var sizeBytes int64
						fmt.Sscanf(fileSize, "%d", &sizeBytes)
						fileSize = fmt.Sprintf("%.2f MB", float64(sizeBytes)/(1024*1024))
					}

					displayName := secret.Name
					if len(displayName) > 28 {
						displayName = displayName[:25] + "..."
					}

					displayID := secret.ID
					if len(displayID) > 28 {
						displayID = displayID[:8] + "..." + displayID[len(displayID)-8:]
					}

					fmt.Printf("%-10s %-30s %-30s %-15s %s\n", status, displayID, displayName, fileSize, mimeType)
				}

				fmt.Println(strings.Repeat("-", 100))
				fmt.Println("✓ synced  ⏳ pending  ⚠ conflict  🗑 deleted")

				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&showDeleted, "deleted", false, "Include deleted binary secrets")

	return cmd
}

// newBinaryDeleteCmd creates the delete binary secret command
func newBinaryDeleteCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var noConfirm bool

	cmd := &cobra.Command{
		Use:     "delete [name or ID]",
		Short:   "Delete a binary secret",
		Long:    "Soft-delete a binary secret (marks as deleted, will sync to server)",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if err := requireAuth(sess); err != nil {
				return err
			}

			identifier := args[0]

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Get secret to confirm
				var secret *storage.LocalSecret
				secret, err := repo.Get(ctx, identifier)
				if err != nil {
					secret, err = repo.GetByName(ctx, identifier)
					if err != nil {
						return fmt.Errorf("binary secret not found: %s", identifier)
					}
				}

				if secret.IsDeleted {
					return fmt.Errorf("binary secret already deleted")
				}

				if secret.Type != pb.SecretType_SECRET_TYPE_BINARY {
					return fmt.Errorf("secret is not a binary file")
				}

				// Confirm deletion
				if !noConfirm {
					var confirm bool
					form := huh.NewForm(
						huh.NewGroup(
							huh.NewConfirm().
								Title(fmt.Sprintf("Delete binary secret '%s'?", secret.Name)).
								Description("This will mark the binary secret as deleted and sync to the server.").
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
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("database operation timed out after 30s")
					}
					return fmt.Errorf("failed to delete binary secret: %w", err)
				}

				logrus.Debugf("Binary secret deleted: id=%s, name=%s", secret.ID, secret.Name)
				fmt.Printf("✓ Binary secret '%s' deleted successfully\n", secret.Name)
				fmt.Printf("  Status: pending sync\n")

				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&noConfirm, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}
