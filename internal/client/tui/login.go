package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/client/sync"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// LoginScreen represents the login screen
type LoginScreen struct {
	ctx  context.Context
	cfg  *config.Config
	sess *session.Session
	repo storage.Repository

	// Form inputs
	usernameInput textinput.Model
	passwordInput textinput.Model
	focusIndex    int

	// State
	loading    bool
	spinner    spinner.Model
	errorMsg   string
	successMsg string
}

// NewLoginScreen creates a new login screen
func NewLoginScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) *LoginScreen {
	// Username input
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Enter username or email"
	usernameInput.Focus()
	usernameInput.CharLimit = 100
	usernameInput.Width = 40

	// Password input
	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter master password"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 40

	// Spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle

	return &LoginScreen{
		ctx:           ctx,
		cfg:           cfg,
		sess:          sess,
		repo:          repo,
		usernameInput: usernameInput,
		passwordInput: passwordInput,
		spinner:       s,
		focusIndex:    0,
	}
}

// Init initializes the login screen
func (s *LoginScreen) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (s *LoginScreen) Update(msg tea.Msg) (*LoginScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if s.focusIndex == 2 {
				// Submit login
				return s, s.performLogin()
			} else if s.focusIndex == 3 {
				// Switch to register screen
				return s, func() tea.Msg {
					return NavigateMsg{Screen: ScreenRegister}
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
			return s, tea.Quit
		}

	case spinner.TickMsg:
		if s.loading {
			s.spinner, cmd = s.spinner.Update(msg)
			return s, cmd
		}

	case loginSuccessMsg:
		s.loading = false
		s.successMsg = "Login successful!"
		// Navigate to secrets list
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretsList}
		}

	case loginErrorMsg:
		s.loading = false
		s.errorMsg = msg.Error()

		return s, nil
	}

	// Update focused input
	if s.focusIndex == 0 {
		s.usernameInput, cmd = s.usernameInput.Update(msg)
	} else if s.focusIndex == 1 {
		s.passwordInput, cmd = s.passwordInput.Update(msg)
	}

	return s, cmd
}

// View renders the login screen
func (s *LoginScreen) View() string {
	// Title
	title := appTitleStyle.Render("🔐 Keyper - Secure Password Manager")

	// Form container
	var form string

	// Username field
	usernameLabel := inputLabelStyle.Render("Username")
	usernameField := s.usernameInput.View()

	// Password field
	passwordLabel := inputLabelStyle.Render("Master Password")
	passwordField := s.passwordInput.View()

	// Login button
	loginBtn := inactiveButtonStyle.Render("[ Login ]")
	if s.focusIndex == 2 {
		loginBtn = buttonStyle.Render("[ Login ]")
	}

	// Register link
	registerLink := inactiveButtonStyle.Render("[ Register ]")
	if s.focusIndex == 3 {
		registerLink = buttonStyle.Render("[ Register ]")
	}

	buttons := lipgloss.JoinHorizontal(lipgloss.Left, loginBtn, registerLink)

	// Build form
	form = lipgloss.JoinVertical(lipgloss.Left,
		usernameLabel,
		usernameField,
		"",
		passwordLabel,
		passwordField,
		"",
		buttons,
	)

	// Add loading spinner if loading
	if s.loading {
		form = lipgloss.JoinVertical(lipgloss.Left,
			form,
			"",
			spinnerStyle.Render(s.spinner.View()+" Logging in..."),
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
	help := renderHelp("tab: next field • enter: login • esc: quit")

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
func (s *LoginScreen) nextField() {
	s.focusIndex = (s.focusIndex + 1) % 4

	if s.focusIndex == 0 {
		s.usernameInput.Focus()
		s.passwordInput.Blur()
	} else if s.focusIndex == 1 {
		s.usernameInput.Blur()
		s.passwordInput.Focus()
	} else {
		s.usernameInput.Blur()
		s.passwordInput.Blur()
	}
}

// prevField moves focus to the previous field
func (s *LoginScreen) prevField() {
	s.focusIndex--
	if s.focusIndex < 0 {
		s.focusIndex = 3
	}

	if s.focusIndex == 0 {
		s.usernameInput.Focus()
		s.passwordInput.Blur()
	} else if s.focusIndex == 1 {
		s.usernameInput.Blur()
		s.passwordInput.Focus()
	} else {
		s.usernameInput.Blur()
		s.passwordInput.Blur()
	}
}

// performLogin performs the login operation
func (s *LoginScreen) performLogin() tea.Cmd {
	username := s.usernameInput.Value()
	password := s.passwordInput.Value()

	// Validate inputs
	if username == "" {
		s.errorMsg = "Username is required"
		return nil
	}

	if password == "" {
		s.errorMsg = "Password is required"
		return nil
	}

	s.loading = true
	s.errorMsg = ""

	return tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			// Generate salts for key derivation
			salt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return loginErrorMsg{err}
			}

			// Derive encryption key
			encryptionKey := crypto.DeriveKey(password, salt)

			// Hash password for authentication
			authSalt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return loginErrorMsg{err}
			}

			authHash := crypto.HashMasterPassword(password, authSalt)

			// Connect to server
			conn, err := grpc.NewClient(s.cfg.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return loginErrorMsg{fmt.Errorf("failed to connect to server: %w", err)}
			}
			defer conn.Close()

			client := pb.NewAuthServiceClient(conn)

			ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
			defer cancel()

			// Call Login RPC
			resp, err := client.Login(ctx, &pb.LoginRequest{
				Username:       username,
				MasterPassword: string(authHash),
				DeviceInfo:     "keyper-tui",
			})
			if err != nil {
				return loginErrorMsg{fmt.Errorf("login failed: %w", err)}
			}

			// Store session data
			s.sess.UserID = resp.UserId
			s.sess.UpdateTokens(resp.AccessToken, resp.RefreshToken, resp.ExpiresAt.AsTime())
			s.sess.SetEncryptionKey(encryptionKey)

			if err := s.sess.Save(); err != nil {
				return loginErrorMsg{fmt.Errorf("failed to save session: %w", err)}
			}

			// Perform initial sync
			opts := &sync.SyncOptions{}
			if _, err := sync.Sync(ctx, s.cfg, s.sess, s.repo, opts); err != nil {
				// Log but don't fail login
				return loginSuccessMsg{}
			}

			return loginSuccessMsg{}
		},
	)
}

type loginSuccessMsg struct{}

type loginErrorMsg struct {
	error
}
