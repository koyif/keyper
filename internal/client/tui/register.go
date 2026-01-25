package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RegisterScreen represents the registration screen
type RegisterScreen struct {
	ctx  context.Context
	cfg  *config.Config
	sess *session.Session
	repo storage.Repository

	// Form inputs
	usernameInput        textinput.Model
	passwordInput        textinput.Model
	confirmPasswordInput textinput.Model
	focusIndex           int

	// State
	loading    bool
	spinner    spinner.Model
	errorMsg   string
	successMsg string
}

// NewRegisterScreen creates a new registration screen
func NewRegisterScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) *RegisterScreen {
	// Username input
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Enter username or email"
	usernameInput.Focus()
	usernameInput.CharLimit = 100
	usernameInput.Width = 40

	// Password input
	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter master password (min 8 chars)"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 40

	// Confirm password input
	confirmPasswordInput := textinput.New()
	confirmPasswordInput.Placeholder = "Confirm master password"
	confirmPasswordInput.EchoMode = textinput.EchoPassword
	confirmPasswordInput.EchoCharacter = '•'
	confirmPasswordInput.CharLimit = 100
	confirmPasswordInput.Width = 40

	// Spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle

	return &RegisterScreen{
		ctx:                  ctx,
		cfg:                  cfg,
		sess:                 sess,
		repo:                 repo,
		usernameInput:        usernameInput,
		passwordInput:        passwordInput,
		confirmPasswordInput: confirmPasswordInput,
		spinner:              s,
		focusIndex:           0,
	}
}

// Init initializes the register screen
func (s *RegisterScreen) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (s *RegisterScreen) Update(msg tea.Msg) (*RegisterScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if s.focusIndex == 3 {
				// Submit registration
				return s, s.performRegister()
			} else if s.focusIndex == 4 {
				// Back to login
				return s, func() tea.Msg {
					return NavigateMsg{Screen: ScreenLogin}
				}
			} else {
				// Move to next field
				s.nextField()
			}

		case "tab":
			s.nextField()

		case "shift+tab":
			s.prevField()

		case "esc":
			// Back to login
			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenLogin}
			}
		}

	case spinner.TickMsg:
		if s.loading {
			s.spinner, cmd = s.spinner.Update(msg)
			return s, cmd
		}

	case registerSuccessMsg:
		s.loading = false
		s.successMsg = "Registration successful!"
		// Navigate to secrets list
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretsList}
		}

	case registerErrorMsg:
		s.loading = false
		s.errorMsg = msg.Error()
		return s, nil
	}

	// Update focused input
	switch s.focusIndex {
	case 0:
		s.usernameInput, cmd = s.usernameInput.Update(msg)
	case 1:
		s.passwordInput, cmd = s.passwordInput.Update(msg)
	case 2:
		s.confirmPasswordInput, cmd = s.confirmPasswordInput.Update(msg)
	}

	return s, cmd
}

// View renders the register screen
func (s *RegisterScreen) View() string {
	// Title
	title := appTitleStyle.Render("🔐 Keyper - Register New Account")

	// Form container
	var form string

	// Username field
	usernameLabel := inputLabelStyle.Render("Username")
	usernameField := s.usernameInput.View()

	// Password field
	passwordLabel := inputLabelStyle.Render("Master Password")
	passwordField := s.passwordInput.View()

	// Confirm password field
	confirmLabel := inputLabelStyle.Render("Confirm Password")
	confirmField := s.confirmPasswordInput.View()

	// Register button
	registerBtn := inactiveButtonStyle.Render("[ Register ]")
	if s.focusIndex == 3 {
		registerBtn = buttonStyle.Render("[ Register ]")
	}

	// Back to login link
	backLink := inactiveButtonStyle.Render("[ Back to Login ]")
	if s.focusIndex == 4 {
		backLink = buttonStyle.Render("[ Back to Login ]")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Left, registerBtn, backLink)

	// Build form
	form = lipgloss.JoinVertical(lipgloss.Left,
		usernameLabel,
		usernameField,
		"",
		passwordLabel,
		passwordField,
		"",
		confirmLabel,
		confirmField,
		"",
		buttons,
	)

	// Add loading spinner if loading
	if s.loading {
		form = lipgloss.JoinVertical(lipgloss.Left,
			form,
			"",
			spinnerStyle.Render(s.spinner.View()+" Registering..."),
		)
	}

	// Add error message if any
	if s.errorMsg != "" {
		form = lipgloss.JoinVertical(lipgloss.Left,
			form,
			"",
			errorStyle.Render("✗ "+s.errorMsg),
		)
	}

	// Add success message if any
	if s.successMsg != "" {
		form = lipgloss.JoinVertical(lipgloss.Left,
			form,
			"",
			successStyle.Render("✓ "+s.successMsg),
		)
	}

	// Container with border
	container := containerStyle.Render(form)

	// Help text
	help := renderHelp("tab: next field • enter: register • esc: back to login")

	// Combine everything
	return lipgloss.JoinVertical(lipgloss.Left,
		"",
		title,
		"",
		container,
		help,
	)
}

// nextField moves focus to the next field
func (s *RegisterScreen) nextField() {
	s.focusIndex = (s.focusIndex + 1) % 5

	s.usernameInput.Blur()
	s.passwordInput.Blur()
	s.confirmPasswordInput.Blur()

	switch s.focusIndex {
	case 0:
		s.usernameInput.Focus()
	case 1:
		s.passwordInput.Focus()
	case 2:
		s.confirmPasswordInput.Focus()
	}
}

// prevField moves focus to the previous field
func (s *RegisterScreen) prevField() {
	s.focusIndex--
	if s.focusIndex < 0 {
		s.focusIndex = 4
	}

	s.usernameInput.Blur()
	s.passwordInput.Blur()
	s.confirmPasswordInput.Blur()

	switch s.focusIndex {
	case 0:
		s.usernameInput.Focus()
	case 1:
		s.passwordInput.Focus()
	case 2:
		s.confirmPasswordInput.Focus()
	}
}

// performRegister performs the registration operation
func (s *RegisterScreen) performRegister() tea.Cmd {
	username := s.usernameInput.Value()
	password := s.passwordInput.Value()
	confirmPassword := s.confirmPasswordInput.Value()

	// Validate inputs
	if username == "" {
		s.errorMsg = "Username is required"
		return nil
	}
	if len(username) < 3 {
		s.errorMsg = "Username must be at least 3 characters"
		return nil
	}
	if password == "" {
		s.errorMsg = "Password is required"
		return nil
	}
	if len(password) < 8 {
		s.errorMsg = "Password must be at least 8 characters"
		return nil
	}
	if password != confirmPassword {
		s.errorMsg = "Passwords do not match"
		return nil
	}

	s.loading = true
	s.errorMsg = ""

	return tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			// Generate salt for key derivation
			salt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return registerErrorMsg{fmt.Errorf("failed to generate salt: %w", err)}
			}

			// Derive encryption key from master password
			encryptionKey := crypto.DeriveKey(password, salt)

			// Hash master password for authentication
			authSalt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return registerErrorMsg{fmt.Errorf("failed to generate auth salt: %w", err)}
			}
			authHash := crypto.HashMasterPassword(password, authSalt)

			// Generate encryption key verifier
			verifier, _, err := crypto.GenerateEncryptionKeyVerifier(encryptionKey)
			if err != nil {
				return registerErrorMsg{fmt.Errorf("failed to generate key verifier: %w", err)}
			}

			// Connect to server
			conn, err := grpc.NewClient(s.cfg.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return registerErrorMsg{fmt.Errorf("failed to connect to server: %w", err)}
			}
			defer conn.Close()

			client := pb.NewAuthServiceClient(conn)
			ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
			defer cancel()

			// Call Register RPC
			resp, err := client.Register(ctx, &pb.RegisterRequest{
				Username:       username,
				MasterPassword: string(authHash),
				DeviceInfo:     "keyper-tui",
			})
			if err != nil {
				return registerErrorMsg{fmt.Errorf("registration failed: %w", err)}
			}

			// Store session data
			s.sess.UserID = resp.UserId
			s.sess.UpdateTokens(resp.AccessToken, resp.RefreshToken, resp.ExpiresAt.AsTime())
			s.sess.EncryptionKeyVerifier = verifier
			s.sess.SetEncryptionKey(encryptionKey)

			if err := s.sess.Save(); err != nil {
				return registerErrorMsg{fmt.Errorf("failed to save session: %w", err)}
			}

			return registerSuccessMsg{}
		},
	)
}

type registerSuccessMsg struct{}

type registerErrorMsg struct {
	error
}
