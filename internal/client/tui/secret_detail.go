package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// SecretDetailScreen represents the secret detail view screen
type SecretDetailScreen struct {
	ctx    context.Context
	cfg    *config.Config
	sess   *session.Session
	repo   storage.Repository
	secret *storage.LocalSecret

	// Decrypted data
	decryptedData map[string]interface{}
	errorMsg      string
	showPassword  bool
}

// NewSecretDetailScreen creates a new secret detail screen
func NewSecretDetailScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository, secret *storage.LocalSecret) *SecretDetailScreen {
	return &SecretDetailScreen{
		ctx:    ctx,
		cfg:    cfg,
		sess:   sess,
		repo:   repo,
		secret: secret,
	}
}

// Init initializes the secret detail screen
func (s *SecretDetailScreen) Init() tea.Cmd {
	return s.decryptSecretCmd()
}

// Update handles messages
func (s *SecretDetailScreen) Update(msg tea.Msg) (*SecretDetailScreen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return s, tea.Quit

		case "esc":
			// Go back to secrets list
			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenSecretsList}
			}

		case "e":
			// Edit secret
			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenSecretEdit, Data: s.secret}
			}

		case "d":
			// Delete secret
			return s, s.deleteSecretCmd()

		case "p":
			// Toggle password visibility
			s.showPassword = !s.showPassword
			return s, nil
		}

	case decryptedMsg:
		s.decryptedData = msg.data
		return s, nil

	case deletedMsg:
		// Go back to list
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretsList}
		}

	case errorMsg:
		s.errorMsg = msg.Error()
		return s, nil
	}

	return s, nil
}

// View renders the secret detail screen
func (s *SecretDetailScreen) View() string {
	// Header
	header := appTitleStyle.Render("🔐 Keyper - Secret Detail")

	// Secret info
	title := titleStyle.Render(s.secret.Name)

	// Type and status
	typeStr := s.formatSecretType(s.secret.Type)
	statusBadge := renderSyncBadge(string(s.secret.SyncStatus))
	info := lipgloss.JoinHorizontal(lipgloss.Left,
		"Type: "+typeStr+"  ",
		statusBadge,
	)

	// Decrypted content
	var content string
	if s.decryptedData != nil {
		content = s.renderDecryptedData()
	} else if s.errorMsg != "" {
		content = errorStyle.Render("✗ Failed to decrypt: " + s.errorMsg)
	} else {
		content = "Loading..."
	}

	// Container
	container := containerStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			title,
			"",
			info,
			"",
			renderDivider(60),
			"",
			content,
		),
	)

	// Help text
	help := renderHelp("e: edit • d: delete • p: toggle password • esc: back • q: quit")

	// Combine everything
	return lipgloss.JoinVertical(lipgloss.Left,
		"",
		header,
		"",
		container,
		help,
	)
}

// renderDecryptedData renders the decrypted secret data
func (s *SecretDetailScreen) renderDecryptedData() string {
	lines := []string{}

	switch s.secret.Type {
	case pb.SecretType_SECRET_TYPE_CREDENTIAL:
		if username, ok := s.decryptedData["username"].(string); ok {
			lines = append(lines, inputLabelStyle.Render("Username:"))
			lines = append(lines, "  "+username)
		}
		if password, ok := s.decryptedData["password"].(string); ok {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("Password:"))
			if s.showPassword {
				lines = append(lines, "  "+password)
			} else {
				lines = append(lines, "  "+strings.Repeat("•", len(password)))
			}
		}
		if url, ok := s.decryptedData["url"].(string); ok && url != "" {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("URL:"))
			lines = append(lines, "  "+url)
		}
		if notes, ok := s.decryptedData["notes"].(string); ok && notes != "" {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("Notes:"))
			lines = append(lines, "  "+notes)
		}

	case pb.SecretType_SECRET_TYPE_TEXT:
		if content, ok := s.decryptedData["content"].(string); ok {
			lines = append(lines, inputLabelStyle.Render("Content:"))
			lines = append(lines, "  "+content)
		}

	case pb.SecretType_SECRET_TYPE_BANK_CARD:
		if cardNumber, ok := s.decryptedData["card_number"].(string); ok {
			lines = append(lines, inputLabelStyle.Render("Card Number:"))
			if s.showPassword {
				lines = append(lines, "  "+cardNumber)
			} else {
				// Mask card number
				if len(cardNumber) > 4 {
					lines = append(lines, "  "+strings.Repeat("*", len(cardNumber)-4)+cardNumber[len(cardNumber)-4:])
				} else {
					lines = append(lines, "  "+strings.Repeat("*", len(cardNumber)))
				}
			}
		}
		if cardHolder, ok := s.decryptedData["card_holder"].(string); ok {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("Card Holder:"))
			lines = append(lines, "  "+cardHolder)
		}
		if expiry, ok := s.decryptedData["expiry"].(string); ok {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("Expiry:"))
			lines = append(lines, "  "+expiry)
		}
		if cvv, ok := s.decryptedData["cvv"].(string); ok {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render("CVV:"))
			if s.showPassword {
				lines = append(lines, "  "+cvv)
			} else {
				lines = append(lines, "  "+strings.Repeat("•", len(cvv)))
			}
		}

	default:
		// Generic JSON display
		for key, value := range s.decryptedData {
			lines = append(lines, "")
			lines = append(lines, inputLabelStyle.Render(key+":"))
			lines = append(lines, "  "+fmt.Sprintf("%v", value))
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// decryptSecretCmd returns a command to decrypt the secret
func (s *SecretDetailScreen) decryptSecretCmd() tea.Cmd {
	return func() tea.Msg {
		// Get encryption key from session
		encryptionKey := s.sess.GetEncryptionKey()
		if encryptionKey == nil {
			return errorMsg{fmt.Errorf("encryption key not available")}
		}

		// Decrypt the data
		decrypted, err := crypto.Decrypt(string(s.secret.EncryptedData), encryptionKey)
		if err != nil {
			return errorMsg{fmt.Errorf("decryption failed: %w", err)}
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(decrypted, &data); err != nil {
			return errorMsg{fmt.Errorf("invalid data format: %w", err)}
		}

		return decryptedMsg{data: data}
	}
}

// deleteSecretCmd returns a command to delete the secret
func (s *SecretDetailScreen) deleteSecretCmd() tea.Cmd {
	return func() tea.Msg {
		if err := s.repo.Delete(s.ctx, s.secret.ID); err != nil {
			return errorMsg{fmt.Errorf("failed to delete secret: %w", err)}
		}
		return deletedMsg{}
	}
}

// formatSecretType formats secret type for display
func (s *SecretDetailScreen) formatSecretType(t pb.SecretType) string {
	switch t {
	case pb.SecretType_SECRET_TYPE_CREDENTIAL:
		return "Credential"
	case pb.SecretType_SECRET_TYPE_TEXT:
		return "Text/Note"
	case pb.SecretType_SECRET_TYPE_BANK_CARD:
		return "Bank Card"
	case pb.SecretType_SECRET_TYPE_BINARY:
		return "Binary"
	default:
		return "Unknown"
	}
}

type decryptedMsg struct {
	data map[string]interface{}
}

type deletedMsg struct{}
