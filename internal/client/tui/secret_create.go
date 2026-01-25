package tui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// SecretCreateScreen represents the secret creation screen
type SecretCreateScreen struct {
	ctx  context.Context
	cfg  *config.Config
	sess *session.Session
	repo storage.Repository

	// Form inputs
	nameInput     textinput.Model
	usernameInput textinput.Model
	passwordInput textinput.Model
	urlInput      textinput.Model
	notesInput    textinput.Model
	focusIndex    int

	// State
	errorMsg   string
	successMsg string
}

// NewSecretCreateScreen creates a new secret creation screen
func NewSecretCreateScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) *SecretCreateScreen {
	s := &SecretCreateScreen{
		ctx:  ctx,
		cfg:  cfg,
		sess: sess,
		repo: repo,
	}

	// Initialize inputs
	s.nameInput = textinput.New()
	s.nameInput.Placeholder = "Secret name"
	s.nameInput.CharLimit = 100
	s.nameInput.Width = 40
	s.nameInput.Focus()

	s.usernameInput = textinput.New()
	s.usernameInput.Placeholder = "Username"
	s.usernameInput.CharLimit = 100
	s.usernameInput.Width = 40

	s.passwordInput = textinput.New()
	s.passwordInput.Placeholder = "Password"
	s.passwordInput.EchoMode = textinput.EchoPassword
	s.passwordInput.EchoCharacter = '•'
	s.passwordInput.CharLimit = 100
	s.passwordInput.Width = 40

	s.urlInput = textinput.New()
	s.urlInput.Placeholder = "URL (optional)"
	s.urlInput.CharLimit = 200
	s.urlInput.Width = 40

	s.notesInput = textinput.New()
	s.notesInput.Placeholder = "Notes (optional)"
	s.notesInput.CharLimit = 500
	s.notesInput.Width = 40

	return s
}

// Init initializes the screen
func (s *SecretCreateScreen) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (s *SecretCreateScreen) Update(msg tea.Msg) (*SecretCreateScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Go back to list
			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenSecretsList}
			}

		case "ctrl+s":
			// Save secret
			return s, s.saveSecretCmd()

		case "tab":
			s.nextField()

		case "shift+tab":
			s.prevField()

		case "enter":
			if s.focusIndex == 5 {
				// Save button
				return s, s.saveSecretCmd()
			}
			s.nextField()
		}

	case secretSavedMsg:
		s.successMsg = "Secret created successfully!"
		// Go back to list
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretsList}
		}

	case errorMsg:
		s.errorMsg = msg.Error()
		return s, nil
	}

	// Update focused input
	switch s.focusIndex {
	case 0:
		s.nameInput, cmd = s.nameInput.Update(msg)
	case 1:
		s.usernameInput, cmd = s.usernameInput.Update(msg)
	case 2:
		s.passwordInput, cmd = s.passwordInput.Update(msg)
	case 3:
		s.urlInput, cmd = s.urlInput.Update(msg)
	case 4:
		s.notesInput, cmd = s.notesInput.Update(msg)
	}

	return s, cmd
}

// View renders the screen
func (s *SecretCreateScreen) View() string {
	// Header
	header := appTitleStyle.Render("🔐 Keyper - Create Secret")

	// Form
	form := lipgloss.JoinVertical(lipgloss.Left,
		inputLabelStyle.Render("Name:"),
		s.nameInput.View(),
		"",
		inputLabelStyle.Render("Username:"),
		s.usernameInput.View(),
		"",
		inputLabelStyle.Render("Password:"),
		s.passwordInput.View(),
		"",
		inputLabelStyle.Render("URL:"),
		s.urlInput.View(),
		"",
		inputLabelStyle.Render("Notes:"),
		s.notesInput.View(),
		"",
	)

	// Save button
	saveBtn := inactiveButtonStyle.Render("[ Save ]")
	if s.focusIndex == 5 {
		saveBtn = buttonStyle.Render("[ Save ]")
	}
	form = lipgloss.JoinVertical(lipgloss.Left, form, saveBtn)

	// Error/success messages
	if s.errorMsg != "" {
		form = lipgloss.JoinVertical(lipgloss.Left, form, "", errorStyle.Render("✗ "+s.errorMsg))
	}
	if s.successMsg != "" {
		form = lipgloss.JoinVertical(lipgloss.Left, form, "", successStyle.Render("✓ "+s.successMsg))
	}

	// Container
	container := containerStyle.Render(form)

	// Help
	help := renderHelp("tab: next field • ctrl+s: save • esc: cancel")

	return lipgloss.JoinVertical(lipgloss.Left,
		"",
		header,
		"",
		container,
		help,
	)
}

// nextField moves to next field
func (s *SecretCreateScreen) nextField() {
	s.focusIndex = (s.focusIndex + 1) % 6

	s.nameInput.Blur()
	s.usernameInput.Blur()
	s.passwordInput.Blur()
	s.urlInput.Blur()
	s.notesInput.Blur()

	switch s.focusIndex {
	case 0:
		s.nameInput.Focus()
	case 1:
		s.usernameInput.Focus()
	case 2:
		s.passwordInput.Focus()
	case 3:
		s.urlInput.Focus()
	case 4:
		s.notesInput.Focus()
	}
}

// prevField moves to previous field
func (s *SecretCreateScreen) prevField() {
	s.focusIndex--
	if s.focusIndex < 0 {
		s.focusIndex = 5
	}

	s.nameInput.Blur()
	s.usernameInput.Blur()
	s.passwordInput.Blur()
	s.urlInput.Blur()
	s.notesInput.Blur()

	switch s.focusIndex {
	case 0:
		s.nameInput.Focus()
	case 1:
		s.usernameInput.Focus()
	case 2:
		s.passwordInput.Focus()
	case 3:
		s.urlInput.Focus()
	case 4:
		s.notesInput.Focus()
	}
}

// saveSecretCmd saves the secret
func (s *SecretCreateScreen) saveSecretCmd() tea.Cmd {
	return func() tea.Msg {
		name := s.nameInput.Value()
		if name == "" {
			return errorMsg{fmt.Errorf("name is required")}
		}

		// Build secret data
		data := map[string]interface{}{
			"username": s.usernameInput.Value(),
			"password": s.passwordInput.Value(),
			"url":      s.urlInput.Value(),
			"notes":    s.notesInput.Value(),
		}

		// Marshal to JSON
		jsonData, err := json.Marshal(data)
		if err != nil {
			return errorMsg{fmt.Errorf("failed to marshal data: %w", err)}
		}

		// Encrypt
		encryptionKey := s.sess.GetEncryptionKey()
		if encryptionKey == nil {
			return errorMsg{fmt.Errorf("encryption key not available")}
		}

		encrypted, err := crypto.Encrypt(jsonData, encryptionKey)
		if err != nil {
			return errorMsg{fmt.Errorf("encryption failed: %w", err)}
		}

		// Create secret
		secret := &storage.LocalSecret{
			ID:            uuid.New().String(),
			Name:          name,
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: []byte(encrypted),
			SyncStatus:    storage.SyncStatusPending,
		}

		if err := s.repo.Create(s.ctx, secret); err != nil {
			return errorMsg{fmt.Errorf("failed to create secret: %w", err)}
		}

		return secretSavedMsg{}
	}
}

type secretSavedMsg struct{}
