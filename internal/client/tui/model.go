package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
)

// ScreenType represents the different screens in the TUI
type ScreenType int

const (
	ScreenLogin ScreenType = iota
	ScreenRegister
	ScreenSecretsList
	ScreenSecretDetail
	ScreenSecretCreate
	ScreenSecretEdit
)

// Model represents the main TUI application model
type Model struct {
	// Application context
	ctx  context.Context
	cfg  *config.Config
	sess *session.Session
	repo storage.Repository

	// Current screen
	currentScreen ScreenType

	// Screen models
	loginScreen        *LoginScreen
	registerScreen     *RegisterScreen
	secretsListScreen  *SecretsListScreen
	secretDetailScreen *SecretDetailScreen
	secretCreateScreen *SecretCreateScreen
	secretEditScreen   *SecretEditScreen

	// Terminal dimensions
	width  int
	height int

	// Error state
	err error
}

// NewModel creates a new TUI application model
func NewModel(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) *Model {
	m := &Model{
		ctx:  ctx,
		cfg:  cfg,
		sess: sess,
		repo: repo,
	}

	// Determine initial screen based on authentication state
	if sess.IsAuthenticated() {
		m.currentScreen = ScreenSecretsList
		m.secretsListScreen = NewSecretsListScreen(ctx, cfg, sess, repo)
	} else {
		m.currentScreen = ScreenLogin
		m.loginScreen = NewLoginScreen(ctx, cfg, sess, repo)
	}

	return m
}

// Init initializes the TUI application
func (m *Model) Init() tea.Cmd {
	// Return initialization command based on current screen
	switch m.currentScreen {
	case ScreenLogin:
		return m.loginScreen.Init()
	case ScreenRegister:
		return m.registerScreen.Init()
	case ScreenSecretsList:
		return m.secretsListScreen.Init()
	case ScreenSecretDetail:
		return m.secretDetailScreen.Init()
	case ScreenSecretCreate:
		return m.secretCreateScreen.Init()
	case ScreenSecretEdit:
		return m.secretEditScreen.Init()
	default:
		return nil
	}
}

// Update handles messages and updates the model
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Global quit shortcut
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case NavigateMsg:
		return m.handleNavigation(msg)

	case ErrorMsg:
		m.err = msg.Err
		return m, nil
	}

	// Delegate to current screen
	switch m.currentScreen {
	case ScreenLogin:
		var cmd tea.Cmd
		m.loginScreen, cmd = m.loginScreen.Update(msg)
		return m, cmd
	case ScreenRegister:
		var cmd tea.Cmd
		m.registerScreen, cmd = m.registerScreen.Update(msg)
		return m, cmd
	case ScreenSecretsList:
		var cmd tea.Cmd
		m.secretsListScreen, cmd = m.secretsListScreen.Update(msg)
		return m, cmd
	case ScreenSecretDetail:
		var cmd tea.Cmd
		m.secretDetailScreen, cmd = m.secretDetailScreen.Update(msg)
		return m, cmd
	case ScreenSecretCreate:
		var cmd tea.Cmd
		m.secretCreateScreen, cmd = m.secretCreateScreen.Update(msg)
		return m, cmd
	case ScreenSecretEdit:
		var cmd tea.Cmd
		m.secretEditScreen, cmd = m.secretEditScreen.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the current screen
func (m *Model) View() string {
	// Show error if any
	if m.err != nil {
		return renderError(m.err)
	}

	// Delegate to current screen
	switch m.currentScreen {
	case ScreenLogin:
		return m.loginScreen.View()
	case ScreenRegister:
		return m.registerScreen.View()
	case ScreenSecretsList:
		return m.secretsListScreen.View()
	case ScreenSecretDetail:
		return m.secretDetailScreen.View()
	case ScreenSecretCreate:
		return m.secretCreateScreen.View()
	case ScreenSecretEdit:
		return m.secretEditScreen.View()
	default:
		return "Unknown screen"
	}
}

// handleNavigation handles screen navigation
func (m *Model) handleNavigation(msg NavigateMsg) (tea.Model, tea.Cmd) {
	m.currentScreen = msg.Screen

	// Initialize the new screen
	switch msg.Screen {
	case ScreenLogin:
		if m.loginScreen == nil {
			m.loginScreen = NewLoginScreen(m.ctx, m.cfg, m.sess, m.repo)
		}
		return m, m.loginScreen.Init()

	case ScreenRegister:
		if m.registerScreen == nil {
			m.registerScreen = NewRegisterScreen(m.ctx, m.cfg, m.sess, m.repo)
		}
		return m, m.registerScreen.Init()

	case ScreenSecretsList:
		if m.secretsListScreen == nil {
			m.secretsListScreen = NewSecretsListScreen(m.ctx, m.cfg, m.sess, m.repo)
		}
		return m, m.secretsListScreen.Init()

	case ScreenSecretDetail:
		if msg.Data != nil {
			if secret, ok := msg.Data.(*storage.LocalSecret); ok {
				m.secretDetailScreen = NewSecretDetailScreen(m.ctx, m.cfg, m.sess, m.repo, secret)
				return m, m.secretDetailScreen.Init()
			}
		}

	case ScreenSecretCreate:
		m.secretCreateScreen = NewSecretCreateScreen(m.ctx, m.cfg, m.sess, m.repo)
		return m, m.secretCreateScreen.Init()

	case ScreenSecretEdit:
		if msg.Data != nil {
			if secret, ok := msg.Data.(*storage.LocalSecret); ok {
				m.secretEditScreen = NewSecretEditScreen(m.ctx, m.cfg, m.sess, m.repo, secret)
				return m, m.secretEditScreen.Init()
			}
		}
	}

	return m, nil
}

// NavigateMsg is a message to navigate to a different screen
type NavigateMsg struct {
	Screen ScreenType
	Data   interface{} // Optional data to pass to the new screen
}

// ErrorMsg is a message to display an error
type ErrorMsg struct {
	Err error
}
