package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Colors
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#04B575")
	errorColor     = lipgloss.Color("#EE6D66")
	warningColor   = lipgloss.Color("#FFAA00")
	mutedColor     = lipgloss.Color("#626262")
	borderColor    = lipgloss.Color("#383838")

	// Base styles
	baseStyle = lipgloss.NewStyle().
			Padding(1, 2)

	// Title styles
	titleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			MarginBottom(1)

	appTitleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			Padding(0, 1).
			Background(lipgloss.Color("#1a1a1a"))

	// Container styles
	containerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(1, 2).
			MarginBottom(1)

	focusedContainerStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(primaryColor).
				Padding(1, 2).
				MarginBottom(1)

	// Input styles
	inputLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			MarginBottom(0).
			Bold(true)

	inputStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#2a2a2a")).
			Padding(0, 1)

	focusedInputStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#3a3a3a")).
				BorderForeground(primaryColor).
				Padding(0, 1)

	// Button styles
	buttonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(primaryColor).
			Padding(0, 2).
			MarginRight(2).
			Bold(true)

	inactiveButtonStyle = lipgloss.NewStyle().
				Foreground(mutedColor).
				Background(lipgloss.Color("#2a2a2a")).
				Padding(0, 2).
				MarginRight(2)

	// Status styles
	successStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	// List styles
	listItemStyle = lipgloss.NewStyle().
			Padding(0, 1)

	selectedListItemStyle = lipgloss.NewStyle().
				Foreground(primaryColor).
				Background(lipgloss.Color("#2a2a2a")).
				Padding(0, 1).
				Bold(true)

	// Table styles
	tableHeaderStyle = lipgloss.NewStyle().
				Foreground(primaryColor).
				Bold(true).
				Align(lipgloss.Center).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Width(20)

	oddRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Padding(0, 1)

	evenRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E0E0")).
			Padding(0, 1)

	// Help/Footer styles
	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(1)

	// Spinner/Loading styles
	spinnerStyle = lipgloss.NewStyle().
			Foreground(primaryColor)

	// Badge styles
	syncPendingBadge = lipgloss.NewStyle().
				Foreground(warningColor).
				Background(lipgloss.Color("#2a2a2a")).
				Padding(0, 1).
				Bold(true)

	syncedBadge = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Background(lipgloss.Color("#2a2a2a")).
			Padding(0, 1).
			Bold(true)

	conflictBadge = lipgloss.NewStyle().
			Foreground(errorColor).
			Background(lipgloss.Color("#2a2a2a")).
			Padding(0, 1).
			Bold(true)

	// Divider
	dividerStyle = lipgloss.NewStyle().
			Foreground(borderColor).
			MarginTop(1).
			MarginBottom(1)
)

// renderError renders an error message
func renderError(err error) string {
	return lipgloss.NewStyle().
		Foreground(errorColor).
		Bold(true).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(errorColor).
		Render("Error: " + err.Error())
}

// renderSuccess renders a success message
func renderSuccess(msg string) string {
	return successStyle.Render("✓ " + msg)
}

// renderWarning renders a warning message
func renderWarning(msg string) string {
	return warningStyle.Render("⚠ " + msg)
}

// renderHelp renders help text
func renderHelp(text string) string {
	return helpStyle.Render(text)
}

// renderDivider renders a horizontal divider
func renderDivider(width int) string {
	return dividerStyle.Width(width).Render("─")
}

// renderSyncBadge renders a badge based on sync status
func renderSyncBadge(status string) string {
	switch status {
	case "pending":
		return syncPendingBadge.Render("PENDING")
	case "synced":
		return syncedBadge.Render("SYNCED")
	case "conflict":
		return conflictBadge.Render("CONFLICT")
	default:
		return ""
	}
}
