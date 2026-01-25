package tui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/crypto"
)

// SecretEditScreen represents the secret edit screen
type SecretEditScreen struct {
	ctx    context.Context
	cfg    *config.Config
	sess   *session.Session
	repo   storage.Repository
	secret *storage.LocalSecret

	// Form inputs
	nameInput     textinput.Model
	usernameInput textinput.Model
	passwordInput textinput.Model
	urlInput      textinput.Model
	notesInput    textinput.Model
	focusIndex    int

	// State
	loaded     bool
	errorMsg   string
	successMsg string
}

// NewSecretEditScreen creates a new secret edit screen
func NewSecretEditScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository, secret *storage.LocalSecret) *SecretEditScreen {
	s := &SecretEditScreen{
		ctx:    ctx,
		cfg:    cfg,
		sess:   sess,
		repo:   repo,
		secret: secret,
	}

	// Initialize inputs
	s.nameInput = textinput.New()
	s.nameInput.CharLimit = 100
	s.nameInput.Width = 40
	s.nameInput.Focus()

	s.usernameInput = textinput.New()
	s.usernameInput.CharLimit = 100
	s.usernameInput.Width = 40

	s.passwordInput = textinput.New()
	s.passwordInput.EchoMode = textinput.EchoPassword
	s.passwordInput.EchoCharacter = '•'
	s.passwordInput.CharLimit = 100
	s.passwordInput.Width = 40

	s.urlInput = textinput.New()
	s.urlInput.CharLimit = 200
	s.urlInput.Width = 40

	s.notesInput = textinput.New()
	s.notesInput.CharLimit = 500
	s.notesInput.Width = 40

	return s
}

// Init initializes the screen
func (s *SecretEditScreen) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		s.loadSecretDataCmd(),
	)
}

// Update handles messages
func (s *SecretEditScreen) Update(msg tea.Msg) (*SecretEditScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Go back to detail view
			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenSecretDetail, Data: s.secret}
			}

		case "ctrl+s":
			// Save changes
			return s, s.saveChangesCmd()

		case "tab":
			s.nextField()

		case "shift+tab":
			s.prevField()

		case "enter":
			if s.focusIndex == 5 {
				// Save button
				return s, s.saveChangesCmd()
			}
			s.nextField()
		}

	case secretLoadedMsg:
		s.loaded = true
		s.nameInput.SetValue(s.secret.Name)
		if data, ok := msg.data["username"].(string); ok {
			s.usernameInput.SetValue(data)
		}
		if data, ok := msg.data["password"].(string); ok {
			s.passwordInput.SetValue(data)
		}
		if data, ok := msg.data["url"].(string); ok {
			s.urlInput.SetValue(data)
		}
		if data, ok := msg.data["notes"].(string); ok {
			s.notesInput.SetValue(data)
		}
		return s, nil

	case secretUpdatedMsg:
		s.successMsg = "Secret updated successfully!"
		// Go back to detail view
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretDetail, Data: s.secret}
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
func (s *SecretEditScreen) View() string {
	// Header
	header := appTitleStyle.Render("🔐 Keyper - Edit Secret")

	if !s.loaded {
		return lipgloss.JoinVertical(lipgloss.Left,
			"",
			header,
			"",
			containerStyle.Render("Loading..."),
		)
	}

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
func (s *SecretEditScreen) nextField() {
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
func (s *SecretEditScreen) prevField() {
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

// loadSecretDataCmd loads and decrypts the secret data
func (s *SecretEditScreen) loadSecretDataCmd() tea.Cmd {
	return func() tea.Msg {
		// Get encryption key
		encryptionKey := s.sess.GetEncryptionKey()
		if encryptionKey == nil {
			return errorMsg{fmt.Errorf("encryption key not available")}
		}

		// Decrypt data
		decrypted, err := crypto.Decrypt(string(s.secret.EncryptedData), encryptionKey)
		if err != nil {
			return errorMsg{fmt.Errorf("decryption failed: %w", err)}
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(decrypted, &data); err != nil {
			return errorMsg{fmt.Errorf("invalid data format: %w", err)}
		}

		return secretLoadedMsg{data: data}
	}
}

// saveChangesCmd saves the changes
func (s *SecretEditScreen) saveChangesCmd() tea.Cmd {
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

		// Update secret
		s.secret.Name = name
		s.secret.EncryptedData = []byte(encrypted)
		s.secret.SyncStatus = storage.SyncStatusPending

		if err := s.repo.Update(s.ctx, s.secret); err != nil {
			return errorMsg{fmt.Errorf("failed to update secret: %w", err)}
		}

		return secretUpdatedMsg{}
	}
}

type secretLoadedMsg struct {
	data map[string]interface{}
}

type secretUpdatedMsg struct{}
