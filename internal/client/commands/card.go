package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
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

// CardMetadata stores additional card info in metadata field
type CardMetadata struct {
	Last4Digits string   `json:"last_4_digits,omitempty"`
	BankName    string   `json:"bank_name,omitempty"`
	Notes       string   `json:"notes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// NewCardCommands returns the card command group
func NewCardCommands(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cardCmd := &cobra.Command{
		Use:     "card",
		Short:   "Manage bank card secrets",
		Long:    "Commands for managing bank card secrets (credit/debit cards)",
		Aliases: []string{"cards"},
	}

	cardCmd.AddCommand(newCardAddCmd(getCfg, getSess, getStorage))
	cardCmd.AddCommand(newCardGetCmd(getCfg, getSess, getStorage))
	cardCmd.AddCommand(newCardListCmd(getCfg, getSess, getStorage))
	cardCmd.AddCommand(newCardUpdateCmd(getCfg, getSess, getStorage))
	cardCmd.AddCommand(newCardDeleteCmd(getCfg, getSess, getStorage))

	return cardCmd
}

// validateCardNumber validates a card number using the Luhn algorithm
func validateCardNumber(cardNumber string) error {
	// Remove spaces and dashes
	cleaned := regexp.MustCompile(`[\s-]`).ReplaceAllString(cardNumber, "")

	// Check if only digits
	if !regexp.MustCompile(`^\d+$`).MatchString(cleaned) {
		return fmt.Errorf("card number must contain only digits")
	}

	// Check length (typically 13-19 digits)
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return fmt.Errorf("card number must be between 13 and 19 digits")
	}

	// Luhn algorithm
	sum := 0
	isEven := false

	// Process digits from right to left
	for i := len(cleaned) - 1; i >= 0; i-- {
		digit, _ := strconv.Atoi(string(cleaned[i]))

		if isEven {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		isEven = !isEven
	}

	if sum%10 != 0 {
		return fmt.Errorf("invalid card number (failed Luhn check)")
	}

	return nil
}

// formatCardNumber formats a card number as XXXX XXXX XXXX XXXX
func formatCardNumber(cardNumber string) string {
	cleaned := regexp.MustCompile(`[\s-]`).ReplaceAllString(cardNumber, "")
	var formatted strings.Builder
	for i, c := range cleaned {
		if i > 0 && i%4 == 0 {
			formatted.WriteString(" ")
		}
		formatted.WriteRune(c)
	}
	return formatted.String()
}

// getLast4Digits extracts the last 4 digits from a card number
func getLast4Digits(cardNumber string) string {
	cleaned := regexp.MustCompile(`[\s-]`).ReplaceAllString(cardNumber, "")
	if len(cleaned) < 4 {
		return cleaned
	}
	return cleaned[len(cleaned)-4:]
}

// newCardAddCmd creates the add card command
func newCardAddCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var (
		nameFlag        string
		cardholderFlag  string
		numberFlag      string
		expiryMonthFlag string
		expiryYearFlag  string
		cvvFlag         string
		pinFlag         string
		bankNameFlag    string
		notesFlag       string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new bank card",
		Long:  "Create a new bank card with cardholder, number, expiry, CVV, and optional PIN",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess := getSess()
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			var name, cardholder, number, expiryMonth, expiryYear, cvv, pin, bankName, notes string

			// Use flags if provided, otherwise prompt interactively
			if nameFlag != "" {
				name = nameFlag
				cardholder = cardholderFlag
				number = numberFlag
				expiryMonth = expiryMonthFlag
				expiryYear = expiryYearFlag
				cvv = cvvFlag
				pin = pinFlag
				bankName = bankNameFlag
				notes = notesFlag

				// Validate card number
				if err := validateCardNumber(number); err != nil {
					return fmt.Errorf("invalid card number: %w", err)
				}
			} else {
				// Interactive prompts
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().
							Title("Name").
							Description("A friendly name for this card (e.g., 'Chase Visa')").
							Value(&name).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("name is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("Cardholder Name").
							Description("Name as it appears on the card").
							Value(&cardholder).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("cardholder name is required")
								}
								return nil
							}),

						huh.NewInput().
							Title("Card Number").
							Description("Full card number (spaces optional)").
							Value(&number).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("card number is required")
								}
								return validateCardNumber(s)
							}),

						huh.NewInput().
							Title("Expiry Month (MM)").
							Description("Two-digit month (e.g., 01, 12)").
							Value(&expiryMonth).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("expiry month is required")
								}
								month, err := strconv.Atoi(s)
								if err != nil || month < 1 || month > 12 {
									return fmt.Errorf("must be 01-12")
								}
								return nil
							}),

						huh.NewInput().
							Title("Expiry Year (YYYY)").
							Description("Four-digit year (e.g., 2025)").
							Value(&expiryYear).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("expiry year is required")
								}
								year, err := strconv.Atoi(s)
								if err != nil || len(s) != 4 {
									return fmt.Errorf("must be a 4-digit year")
								}
								currentYear := time.Now().Year()
								if year < currentYear {
									return fmt.Errorf("card has expired")
								}
								return nil
							}),

						huh.NewInput().
							Title("CVV").
							Description("3 or 4 digit security code").
							Value(&cvv).
							EchoMode(huh.EchoModePassword).
							Validate(func(s string) error {
								if len(s) == 0 {
									return fmt.Errorf("CVV is required")
								}
								if len(s) < 3 || len(s) > 4 {
									return fmt.Errorf("CVV must be 3 or 4 digits")
								}
								if _, err := strconv.Atoi(s); err != nil {
									return fmt.Errorf("CVV must be numeric")
								}
								return nil
							}),

						huh.NewInput().
							Title("PIN (optional)").
							Description("Card PIN if applicable").
							Value(&pin).
							EchoMode(huh.EchoModePassword),

						huh.NewInput().
							Title("Bank Name (optional)").
							Description("Issuing bank name").
							Value(&bankName),

						huh.NewInput().
							Title("Notes (optional)").
							Description("Additional notes").
							Value(&notes),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("operation cancelled: %w", err)
				}
			}

			// Format card number
			number = formatCardNumber(number)

			// Create card data
			cardData := &pb.BankCardData{
				CardholderName: cardholder,
				CardNumber:     number,
				ExpiryMonth:    expiryMonth,
				ExpiryYear:     expiryYear,
				Cvv:            cvv,
				Pin:            pin,
				BankName:       bankName,
			}

			// Marshal card data to JSON
			cardJSON, err := protojson.Marshal(cardData)
			if err != nil {
				return fmt.Errorf("failed to marshal card data: %w", err)
			}

			// Encrypt the card data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			encryptedData, err := crypto.Encrypt(cardJSON, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt card: %w", err)
			}

			// Create metadata with last 4 digits and bank name for list view
			cardMeta := CardMetadata{
				Last4Digits: getLast4Digits(number),
				BankName:    bankName,
				Notes:       notes,
			}
			metadataJSON, err := json.Marshal(cardMeta)
			if err != nil {
				return fmt.Errorf("failed to marshal metadata: %w", err)
			}

			// Create local secret
			now := time.Now()
			secret := &storage.LocalSecret{
				ID:             uuid.New().String(),
				Name:           name,
				Type:           pb.SecretType_SECRET_TYPE_BANK_CARD,
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
				return fmt.Errorf("failed to store card: %w", err)
			}

			logrus.Debugf("Card created: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Card '%s' added successfully\n", name)
			fmt.Printf("  ID: %s\n", secret.ID)
			if bankName != "" {
				fmt.Printf("  Bank: %s\n", bankName)
			}
			fmt.Printf("  Last 4 digits: •••• %s\n", cardMeta.Last4Digits)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	// Add flags for non-interactive mode
	cmd.Flags().StringVar(&nameFlag, "name", "", "Card name")
	cmd.Flags().StringVar(&cardholderFlag, "cardholder", "", "Cardholder name")
	cmd.Flags().StringVar(&numberFlag, "number", "", "Card number")
	cmd.Flags().StringVar(&expiryMonthFlag, "expiry-month", "", "Expiry month (MM)")
	cmd.Flags().StringVar(&expiryYearFlag, "expiry-year", "", "Expiry year (YYYY)")
	cmd.Flags().StringVar(&cvvFlag, "cvv", "", "CVV")
	cmd.Flags().StringVar(&pinFlag, "pin", "", "PIN")
	cmd.Flags().StringVar(&bankNameFlag, "bank", "", "Bank name")
	cmd.Flags().StringVar(&notesFlag, "notes", "", "Additional notes")

	return cmd
}

// newCardGetCmd creates the get card command
func newCardGetCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [name or ID]",
		Short: "Get a bank card by name or ID",
		Long:  "Retrieve and decrypt a bank card, displaying its details",
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
					return fmt.Errorf("card not found: %s", identifier)
				}
			}

			// Check if deleted
			if secret.IsDeleted {
				return fmt.Errorf("card has been deleted")
			}

			// Check type
			if secret.Type != pb.SecretType_SECRET_TYPE_BANK_CARD {
				return fmt.Errorf("secret is not a bank card (type: %s)", secret.Type)
			}

			// Decrypt the data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt card: %w", err)
			}

			// Unmarshal card data
			var cardData pb.BankCardData
			if err := protojson.Unmarshal(decryptedData, &cardData); err != nil {
				return fmt.Errorf("failed to unmarshal card data: %w", err)
			}

			// Display card
			fmt.Printf("\nBank Card: %s\n", secret.Name)
			fmt.Printf("ID: %s\n", secret.ID)
			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("Cardholder: %s\n", cardData.CardholderName)
			fmt.Printf("Card Number: %s\n", cardData.CardNumber)
			fmt.Printf("Expiry: %s/%s\n", cardData.ExpiryMonth, cardData.ExpiryYear)
			fmt.Printf("CVV: %s\n", cardData.Cvv)
			if cardData.Pin != "" {
				fmt.Printf("PIN: %s\n", cardData.Pin)
			}
			if cardData.BankName != "" {
				fmt.Printf("Bank: %s\n", cardData.BankName)
			}

			// Display metadata if present
			if secret.Metadata != "" {
				var cardMeta CardMetadata
				if err := json.Unmarshal([]byte(secret.Metadata), &cardMeta); err == nil {
					if cardMeta.Notes != "" {
						fmt.Printf("Notes: %s\n", cardMeta.Notes)
					}
				}
			}

			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("Created: %s\n", secret.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format(time.RFC3339))
			fmt.Printf("Sync Status: %s\n", secret.SyncStatus)

			return nil
		},
	}

	return cmd
}

// newCardListCmd creates the list cards command
func newCardListCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var showDeleted bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all bank cards",
		Long:    "Display a list of all stored bank cards",
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
			cardType := pb.SecretType_SECRET_TYPE_BANK_CARD

			// List cards
			secrets, err := repo.List(ctx, storage.ListFilters{
				Type:           &cardType,
				IncludeDeleted: showDeleted,
			})
			if err != nil {
				return fmt.Errorf("failed to list cards: %w", err)
			}

			if len(secrets) == 0 {
				fmt.Println("No bank cards found")
				return nil
			}

			// Display cards
			fmt.Printf("\nBank Cards (%d):\n", len(secrets))
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

				// Get metadata for display
				var cardMeta CardMetadata
				info := ""
				if secret.Metadata != "" {
					if err := json.Unmarshal([]byte(secret.Metadata), &cardMeta); err == nil {
						parts := []string{}
						if cardMeta.Last4Digits != "" {
							parts = append(parts, "•••• "+cardMeta.Last4Digits)
						}
						if cardMeta.BankName != "" {
							parts = append(parts, cardMeta.BankName)
						}
						if len(parts) > 0 {
							info = " (" + strings.Join(parts, ", ") + ")"
						}
					}
				}

				fmt.Printf("%s %-36s  %s%s\n", status, secret.ID[:8]+"...", secret.Name, info)
			}

			fmt.Println(strings.Repeat("-", 80))
			fmt.Println("✓ synced  ⏳ pending  ⚠ conflict  🗑 deleted")

			return nil
		},
	}

	cmd.Flags().BoolVar(&showDeleted, "deleted", false, "Include deleted cards")

	return cmd
}

// newCardUpdateCmd creates the update card command
func newCardUpdateCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [name or ID]",
		Short: "Update an existing bank card",
		Long:  "Modify an existing bank card's fields",
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
					return fmt.Errorf("card not found: %s", identifier)
				}
			}

			if secret.IsDeleted {
				return fmt.Errorf("card has been deleted")
			}

			if secret.Type != pb.SecretType_SECRET_TYPE_BANK_CARD {
				return fmt.Errorf("secret is not a bank card")
			}

			// Decrypt existing data
			encryptionKey := sess.GetEncryptionKey()
			if encryptionKey == nil {
				return fmt.Errorf("encryption key not found in session")
			}

			decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt card: %w", err)
			}

			var cardData pb.BankCardData
			if err := protojson.Unmarshal(decryptedData, &cardData); err != nil {
				return fmt.Errorf("failed to unmarshal card data: %w", err)
			}

			// Prompt for updates
			newName := secret.Name
			newCardholder := cardData.CardholderName
			newNumber := cardData.CardNumber
			newExpiryMonth := cardData.ExpiryMonth
			newExpiryYear := cardData.ExpiryYear
			newCvv := cardData.Cvv
			newPin := cardData.Pin
			newBankName := cardData.BankName

			var cardMeta CardMetadata
			if secret.Metadata != "" {
				json.Unmarshal([]byte(secret.Metadata), &cardMeta)
			}
			newNotes := cardMeta.Notes

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
						Title("Cardholder Name").
						Value(&newCardholder).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("cardholder name is required")
							}
							return nil
						}),

					huh.NewInput().
						Title("Card Number").
						Value(&newNumber).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("card number is required")
							}
							return validateCardNumber(s)
						}),

					huh.NewInput().
						Title("Expiry Month (MM)").
						Value(&newExpiryMonth).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("expiry month is required")
							}
							month, err := strconv.Atoi(s)
							if err != nil || month < 1 || month > 12 {
								return fmt.Errorf("must be 01-12")
							}
							return nil
						}),

					huh.NewInput().
						Title("Expiry Year (YYYY)").
						Value(&newExpiryYear).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("expiry year is required")
							}
							_, err := strconv.Atoi(s)
							if err != nil || len(s) != 4 {
								return fmt.Errorf("must be a 4-digit year")
							}
							return nil
						}),

					huh.NewInput().
						Title("CVV").
						Value(&newCvv).
						EchoMode(huh.EchoModePassword).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("CVV is required")
							}
							if len(s) < 3 || len(s) > 4 {
								return fmt.Errorf("CVV must be 3 or 4 digits")
							}
							return nil
						}),

					huh.NewInput().
						Title("PIN").
						Value(&newPin).
						EchoMode(huh.EchoModePassword),

					huh.NewInput().
						Title("Bank Name").
						Value(&newBankName),

					huh.NewInput().
						Title("Notes").
						Value(&newNotes),
				),
			)

			if err := form.Run(); err != nil {
				return fmt.Errorf("operation cancelled: %w", err)
			}

			// Format card number
			newNumber = formatCardNumber(newNumber)

			// Update card data
			cardData.CardholderName = newCardholder
			cardData.CardNumber = newNumber
			cardData.ExpiryMonth = newExpiryMonth
			cardData.ExpiryYear = newExpiryYear
			cardData.Cvv = newCvv
			cardData.Pin = newPin
			cardData.BankName = newBankName

			// Marshal and encrypt
			cardJSON, err := protojson.Marshal(&cardData)
			if err != nil {
				return fmt.Errorf("failed to marshal card data: %w", err)
			}

			encryptedData, err := crypto.Encrypt(cardJSON, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt card: %w", err)
			}

			// Update metadata
			cardMeta.Last4Digits = getLast4Digits(newNumber)
			cardMeta.BankName = newBankName
			cardMeta.Notes = newNotes
			metadataJSON, err := json.Marshal(cardMeta)
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
				return fmt.Errorf("failed to update card: %w", err)
			}

			logrus.Debugf("Card updated: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Card '%s' updated successfully\n", newName)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	return cmd
}

// newCardDeleteCmd creates the delete card command
func newCardDeleteCmd(_ func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var noConfirm bool

	cmd := &cobra.Command{
		Use:     "delete [name or ID]",
		Short:   "Delete a bank card",
		Long:    "Soft-delete a bank card (marks as deleted, will sync to server)",
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
					return fmt.Errorf("card not found: %s", identifier)
				}
			}

			if secret.IsDeleted {
				return fmt.Errorf("card already deleted")
			}

			if secret.Type != pb.SecretType_SECRET_TYPE_BANK_CARD {
				return fmt.Errorf("secret is not a bank card")
			}

			// Confirm deletion
			if !noConfirm {
				var confirm bool
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title(fmt.Sprintf("Delete card '%s'?", secret.Name)).
							Description("This will mark the card as deleted and sync to the server.").
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
				return fmt.Errorf("failed to delete card: %w", err)
			}

			logrus.Debugf("Card deleted: id=%s, name=%s", secret.ID, secret.Name)
			fmt.Printf("✓ Card '%s' deleted successfully\n", secret.Name)
			fmt.Printf("  Status: pending sync\n")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&noConfirm, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}
