package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/client/sync"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SecretsListScreen represents the secrets list screen
type SecretsListScreen struct {
	ctx  context.Context
	cfg  *config.Config
	sess *session.Session
	repo storage.Repository

	// UI components
	table       table.Model
	searchInput textinput.Model
	spinner     spinner.Model

	// Data
	secrets      []*storage.LocalSecret
	filteredType *pb.SecretType
	searchQuery  string

	// State
	loading       bool
	syncing       bool
	searchMode    bool
	errorMsg      string
	successMsg    string
	pendingCount  int
	conflictCount int
}

// NewSecretsListScreen creates a new secrets list screen
func NewSecretsListScreen(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) *SecretsListScreen {
	s := &SecretsListScreen{
		ctx:  ctx,
		cfg:  cfg,
		sess: sess,
		repo: repo,
	}

	// Initialize search input
	s.searchInput = textinput.New()
	s.searchInput.Placeholder = "Search secrets..."
	s.searchInput.CharLimit = 100
	s.searchInput.Width = 40

	// Initialize spinner
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.spinner.Style = spinnerStyle

	// Initialize table
	s.initTable()

	// Load secrets
	s.loadSecrets()

	return s
}

// Init initializes the secrets list screen
func (s *SecretsListScreen) Init() tea.Cmd {
	return tea.Batch(
		s.loadSecretsCmd(),
		s.loadSyncStatusCmd(),
	)
}

// Update handles messages
func (s *SecretsListScreen) Update(msg tea.Msg) (*SecretsListScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if s.searchMode {
			return s.handleSearchMode(msg)
		}

		return s.handleNormalMode(msg)

	case spinner.TickMsg:
		if s.loading || s.syncing {
			s.spinner, cmd = s.spinner.Update(msg)
			return s, cmd
		}

	case secretsLoadedMsg:
		s.loading = false
		s.secrets = msg.secrets
		s.updateTable()

		return s, nil

	case syncStatusMsg:
		s.pendingCount = msg.pendingCount
		s.conflictCount = msg.conflictCount

		return s, nil

	case syncCompleteMsg:
		s.syncing = false
		s.successMsg = msg.message

		return s, tea.Batch(
			s.loadSecretsCmd(),
			s.loadSyncStatusCmd(),
		)

	case errorMsg:
		s.loading = false
		s.syncing = false
		s.errorMsg = msg.Error()

		return s, nil
	}

	// Update table
	s.table, cmd = s.table.Update(msg)

	return s, cmd
}

// handleNormalMode handles key input in normal mode
func (s *SecretsListScreen) handleNormalMode(msg tea.KeyMsg) (*SecretsListScreen, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return s, tea.Quit

	case "enter":
		// View selected secret
		if len(s.secrets) > 0 && s.table.Cursor() < len(s.secrets) {
			secret := s.secrets[s.table.Cursor()]

			return s, func() tea.Msg {
				return NavigateMsg{Screen: ScreenSecretDetail, Data: secret}
			}
		}

	case "n":
		// Create new secret
		return s, func() tea.Msg {
			return NavigateMsg{Screen: ScreenSecretCreate}
		}

	case "/":
		// Enter search mode
		s.searchMode = true
		s.searchInput.Focus()

		return s, textinput.Blink

	case "s":
		// Trigger sync
		if !s.syncing {
			s.syncing = true
			s.successMsg = ""
			s.errorMsg = ""

			return s, tea.Batch(
				s.spinner.Tick,
				s.performSyncCmd(),
			)
		}

	case "r":
		// Reload secrets
		s.loading = true

		return s, tea.Batch(
			s.spinner.Tick,
			s.loadSecretsCmd(),
			s.loadSyncStatusCmd(),
		)

	case "1", "2", "3", "4":
		// Filter by type
		typeMap := map[string]pb.SecretType{
			"1": pb.SecretType_SECRET_TYPE_CREDENTIAL,
			"2": pb.SecretType_SECRET_TYPE_TEXT,
			"3": pb.SecretType_SECRET_TYPE_BANK_CARD,
			"4": pb.SecretType_SECRET_TYPE_BINARY,
		}
		if secretType, ok := typeMap[msg.String()]; ok {
			s.filteredType = &secretType
			s.updateTable()
		}

	case "0":
		// Clear filter
		s.filteredType = nil
		s.updateTable()
	}

	var cmd tea.Cmd

	s.table, cmd = s.table.Update(msg)

	return s, cmd
}

// handleSearchMode handles key input in search mode
func (s *SecretsListScreen) handleSearchMode(msg tea.KeyMsg) (*SecretsListScreen, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "esc":
		// Exit search mode
		s.searchMode = false
		s.searchInput.Blur()
		s.searchQuery = ""
		s.updateTable()

		return s, nil

	case "enter":
		// Apply search
		s.searchMode = false
		s.searchInput.Blur()
		s.searchQuery = s.searchInput.Value()
		s.updateTable()

		return s, nil
	}

	s.searchInput, cmd = s.searchInput.Update(msg)

	return s, cmd
}

// View renders the secrets list screen
func (s *SecretsListScreen) View() string {
	// Header
	header := appTitleStyle.Render("🔐 Keyper - Secrets")

	// Sync status bar
	syncStatus := s.renderSyncStatus()

	// Search bar (if in search mode)
	var searchBar string
	if s.searchMode {
		searchBar = lipgloss.JoinVertical(lipgloss.Left,
			inputLabelStyle.Render("Search:"),
			s.searchInput.View(),
			"",
		)
	}

	// Table
	tableView := s.table.View()

	// Loading/syncing indicator
	var statusIndicator string
	if s.loading {
		statusIndicator = spinnerStyle.Render(s.spinner.View() + " Loading secrets...")
	} else if s.syncing {
		statusIndicator = spinnerStyle.Render(s.spinner.View() + " Syncing with server...")
	}

	// Error message
	var errorView string
	if s.errorMsg != "" {
		errorView = errorStyle.Render("✗ " + s.errorMsg)
	}

	// Success message
	var successView string
	if s.successMsg != "" {
		successView = successStyle.Render("✓ " + s.successMsg)
	}

	// Help text
	help := renderHelp("↑/↓: navigate • enter: view • n: new • /: search • s: sync • r: reload • 0-4: filter • q: quit")

	// Combine everything
	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		syncStatus,
		"",
		searchBar,
		tableView,
		"",
	)

	if statusIndicator != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content, statusIndicator)
	}

	if errorView != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content, "", errorView)
	}

	if successView != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content, "", successView)
	}

	content = lipgloss.JoinVertical(lipgloss.Left, content, "", help)

	return content
}

// initTable initializes the table
func (s *SecretsListScreen) initTable() {
	columns := []table.Column{
		{Title: "Name", Width: 30},
		{Title: "Type", Width: 15},
		{Title: "Status", Width: 12},
		{Title: "Updated", Width: 20},
	}

	s.table = table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	// Style the table
	tableStyle := table.DefaultStyles()
	tableStyle.Header = tableHeaderStyle
	tableStyle.Selected = selectedListItemStyle
	s.table.SetStyles(tableStyle)
}

// updateTable updates the table with filtered/searched secrets
func (s *SecretsListScreen) updateTable() {
	var filtered []*storage.LocalSecret

	for _, secret := range s.secrets {
		// Skip deleted secrets
		if secret.IsDeleted {
			continue
		}

		// Apply type filter
		if s.filteredType != nil && secret.Type != *s.filteredType {
			continue
		}

		// Apply search query
		if s.searchQuery != "" && !strings.Contains(strings.ToLower(secret.Name), strings.ToLower(s.searchQuery)) {
			continue
		}

		filtered = append(filtered, secret)
	}

	// Convert to table rows
	rows := make([]table.Row, 0, len(filtered))
	for _, secret := range filtered {
		rows = append(rows, table.Row{
			secret.Name,
			s.formatSecretType(secret.Type),
			renderSyncBadge(string(secret.SyncStatus)),
			s.formatTime(secret.UpdatedAt),
		})
	}

	s.table.SetRows(rows)
}

// loadSecrets loads secrets from the repository
func (s *SecretsListScreen) loadSecrets() {
	secrets, err := s.repo.List(s.ctx, storage.ListFilters{
		IncludeDeleted: false,
	})
	if err != nil {
		s.errorMsg = fmt.Sprintf("Failed to load secrets: %v", err)
		return
	}

	s.secrets = secrets
	s.updateTable()
}

// loadSecretsCmd returns a command to load secrets
func (s *SecretsListScreen) loadSecretsCmd() tea.Cmd {
	return func() tea.Msg {
		secrets, err := s.repo.List(s.ctx, storage.ListFilters{
			IncludeDeleted: false,
		})
		if err != nil {
			return errorMsg{err}
		}

		return secretsLoadedMsg{secrets: secrets}
	}
}

// loadSyncStatusCmd returns a command to load sync status
func (s *SecretsListScreen) loadSyncStatusCmd() tea.Cmd {
	return func() tea.Msg {
		pending, err := s.repo.GetPendingSync(s.ctx)
		if err != nil {
			return errorMsg{err}
		}

		conflicts, err := s.repo.GetUnresolvedConflicts(s.ctx)
		if err != nil {
			return errorMsg{err}
		}

		return syncStatusMsg{
			pendingCount:  len(pending),
			conflictCount: len(conflicts),
		}
	}
}

// performSyncCmd returns a command to perform sync
func (s *SecretsListScreen) performSyncCmd() tea.Cmd {
	return func() tea.Msg {
		opts := &sync.SyncOptions{}

		result, err := sync.Sync(s.ctx, s.cfg, s.sess, s.repo, opts)
		if err != nil {
			return errorMsg{err}
		}

		message := fmt.Sprintf("Sync complete: %d pushed, %d pulled, %d conflicts",
			result.PushedSecrets, result.PulledSecrets, result.ConflictCount)

		return syncCompleteMsg{message: message}
	}
}

// renderSyncStatus renders the sync status bar
func (s *SecretsListScreen) renderSyncStatus() string {
	lastSync := "Never"
	if !s.sess.LastSyncAt.IsZero() {
		lastSync = s.formatTime(s.sess.LastSyncAt)
	}

	status := fmt.Sprintf("Last sync: %s", lastSync)

	if s.pendingCount > 0 {
		status += fmt.Sprintf(" • %s pending changes", syncPendingBadge.Render(fmt.Sprintf("%d", s.pendingCount)))
	}

	if s.conflictCount > 0 {
		status += fmt.Sprintf(" • %s conflicts", conflictBadge.Render(fmt.Sprintf("%d", s.conflictCount)))
	}

	return containerStyle.Render(status)
}

// formatSecretType formats secret type for display
func (s *SecretsListScreen) formatSecretType(t pb.SecretType) string {
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

// formatTime formats a timestamp for display
func (s *SecretsListScreen) formatTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < time.Minute {
		return "Just now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%d min ago", int(diff.Minutes()))
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	} else if diff < 7*24*time.Hour {
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	}

	return t.Format("2006-01-02")
}

// Message types
type secretsLoadedMsg struct {
	secrets []*storage.LocalSecret
}

type syncStatusMsg struct {
	pendingCount  int
	conflictCount int
}

type syncCompleteMsg struct {
	message string
}

type errorMsg struct {
	error
}
