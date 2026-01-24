package output

import (
	"bytes"
	"fmt"
	"text/template"
	"time"

	"github.com/fatih/color"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// TextFormatter formats data as human-readable text with color
type TextFormatter struct {
	credentialTemplate *template.Template
	textTemplate       *template.Template
	cardTemplate       *template.Template
	binaryTemplate     *template.Template
}

// NewTextFormatter creates a new text formatter with color support
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		credentialTemplate: template.Must(template.New("credential").Funcs(templateFuncs()).Parse(credentialTemplate)),
		textTemplate:       template.Must(template.New("text").Funcs(templateFuncs()).Parse(textNoteTemplate)),
		cardTemplate:       template.Must(template.New("card").Funcs(templateFuncs()).Parse(cardTemplate)),
		binaryTemplate:     template.Must(template.New("binary").Funcs(templateFuncs()).Parse(binaryTemplate)),
	}
}

// templateFuncs returns template functions for formatting
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"bold":    color.New(color.Bold).Sprint,
		"cyan":    color.CyanString,
		"green":   color.GreenString,
		"yellow":  color.YellowString,
		"red":     color.RedString,
		"blue":    color.BlueString,
		"magenta": color.MagentaString,
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"syncIcon": func(status string) string {
			switch status {
			case "synced":
				return color.GreenString("✓")
			case "pending":
				return color.YellowString("⏳")
			case "conflict":
				return color.RedString("⚠")
			default:
				return status
			}
		},
	}
}

// Format formats a single secret item as text
func (f *TextFormatter) Format(data interface{}) (string, error) {
	// Handle different types
	switch v := data.(type) {
	case *CredentialView:
		return f.formatTemplate(f.credentialTemplate, v)
	case *TextView:
		return f.formatTemplate(f.textTemplate, v)
	case *CardView:
		return f.formatTemplate(f.cardTemplate, v)
	case *BinaryView:
		return f.formatTemplate(f.binaryTemplate, v)
	case map[string]interface{}:
		// Try to determine type from the map
		if typeVal, ok := v["type"].(string); ok {
			return f.formatMapByType(typeVal, v)
		}
		return fmt.Sprintf("%+v\n", v), nil
	default:
		return fmt.Sprintf("%+v\n", data), nil
	}
}

// FormatList formats a list of items as text
func (f *TextFormatter) FormatList(data interface{}) (string, error) {
	switch v := data.(type) {
	case []ListItem:
		return f.formatListItems(v)
	case []*ListItem:
		items := make([]ListItem, len(v))
		for i, item := range v {
			items[i] = *item
		}
		return f.formatListItems(items)
	default:
		return fmt.Sprintf("%+v\n", data), nil
	}
}

// formatTemplate applies a template to data
func (f *TextFormatter) formatTemplate(tmpl *template.Template, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		// Fallback to JSON on template error
		return f.fallbackToJSON(data)
	}
	return buf.String(), nil
}

// formatMapByType formats a map based on its type field
func (f *TextFormatter) formatMapByType(typeStr string, data map[string]interface{}) (string, error) {
	switch typeStr {
	case "credential":
		return f.formatTemplate(f.credentialTemplate, data)
	case "text":
		return f.formatTemplate(f.textTemplate, data)
	case "card":
		return f.formatTemplate(f.cardTemplate, data)
	case "binary":
		return f.formatTemplate(f.binaryTemplate, data)
	default:
		return fmt.Sprintf("%+v\n", data), nil
	}
}

// formatListItems formats a list of items
func (f *TextFormatter) formatListItems(items []ListItem) (string, error) {
	if len(items) == 0 {
		return "No items found\n", nil
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("\n%s (%d):\n\n", color.New(color.Bold).Sprint("Items"), len(items)))

	for _, item := range items {
		icon := templateFuncs()["syncIcon"].(func(string) string)(item.SyncStatus)
		typeColor := color.CyanString
		switch item.Type {
		case pb.SecretType_SECRET_TYPE_CREDENTIAL:
			typeColor = color.BlueString
		case pb.SecretType_SECRET_TYPE_TEXT:
			typeColor = color.GreenString
		case pb.SecretType_SECRET_TYPE_BANK_CARD:
			typeColor = color.MagentaString
		case pb.SecretType_SECRET_TYPE_BINARY:
			typeColor = color.YellowString
		}

		typeStr := formatSecretType(item.Type)
		deletedStr := ""
		if item.IsDeleted {
			deletedStr = color.RedString(" 🗑")
		}

		buf.WriteString(fmt.Sprintf("  %s %s %s%s\n",
			icon,
			color.New(color.Bold).Sprint(item.Name),
			typeColor(typeStr),
			deletedStr,
		))
		buf.WriteString(fmt.Sprintf("    ID: %s\n", color.New(color.Faint).Sprint(item.ID)))
		buf.WriteString(fmt.Sprintf("    Updated: %s\n", item.UpdatedAt.Format("2006-01-02 15:04:05")))
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// fallbackToJSON falls back to JSON formatting on error
func (f *TextFormatter) fallbackToJSON(data interface{}) (string, error) {
	formatter := NewJSONFormatter()
	return formatter.Format(data)
}

// formatSecretType converts a SecretType to a readable string
func formatSecretType(t pb.SecretType) string {
	switch t {
	case pb.SecretType_SECRET_TYPE_CREDENTIAL:
		return "Credential"
	case pb.SecretType_SECRET_TYPE_TEXT:
		return "Text"
	case pb.SecretType_SECRET_TYPE_BANK_CARD:
		return "Card"
	case pb.SecretType_SECRET_TYPE_BINARY:
		return "Binary"
	default:
		return "Unknown"
	}
}

// View types for formatting

// CredentialView represents a credential for display
type CredentialView struct {
	Name       string
	ID         string
	Username   string
	Password   string
	Email      string
	URL        string
	Notes      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	SyncStatus string
}

// TextView represents a text note for display
type TextView struct {
	Name       string
	ID         string
	Content    string
	Tags       []string
	Notes      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	SyncStatus string
}

// CardView represents a credit card for display
type CardView struct {
	Name           string
	ID             string
	CardholderName string
	CardNumber     string
	ExpiryDate     string
	CVV            string
	PIN            string
	BankName       string
	Notes          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	SyncStatus     string
}

// BinaryView represents a binary file for display
type BinaryView struct {
	Name       string
	ID         string
	Filename   string
	MimeType   string
	Size       int64
	Notes      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	SyncStatus string
}

// ListItem represents a summary item for list views
type ListItem struct {
	ID         string
	Name       string
	Type       pb.SecretType
	UpdatedAt  time.Time
	SyncStatus string
	IsDeleted  bool
}

// Templates

const credentialTemplate = `
{{ bold "Credential:" }} {{ cyan .Name }}
{{ bold "ID:" }} {{ .ID }}
{{ bold "Username:" }} {{ .Username }}
{{ bold "Password:" }} {{ .Password }}
{{- if .Email }}
{{ bold "Email:" }} {{ .Email }}
{{- end }}
{{- if .URL }}
{{ bold "URL:" }} {{ .URL }}
{{- end }}
{{- if .Notes }}
{{ bold "Notes:" }} {{ .Notes }}
{{- end }}

{{ bold "Created:" }} {{ formatTime .CreatedAt }}
{{ bold "Updated:" }} {{ formatTime .UpdatedAt }}
{{ bold "Sync Status:" }} {{ syncIcon .SyncStatus }} {{ .SyncStatus }}
`

const textNoteTemplate = `
{{ bold "Text Note:" }} {{ cyan .Name }}
{{ bold "ID:" }} {{ .ID }}
{{ bold "Content:" }}
{{ .Content }}
{{- if .Tags }}
{{ bold "Tags:" }} {{ range .Tags }}{{ green . }} {{ end }}
{{- end }}
{{- if .Notes }}
{{ bold "Notes:" }} {{ .Notes }}
{{- end }}

{{ bold "Created:" }} {{ formatTime .CreatedAt }}
{{ bold "Updated:" }} {{ formatTime .UpdatedAt }}
{{ bold "Sync Status:" }} {{ syncIcon .SyncStatus }} {{ .SyncStatus }}
`

const cardTemplate = `
{{ bold "Credit Card:" }} {{ cyan .Name }}
{{ bold "ID:" }} {{ .ID }}
{{ bold "Cardholder:" }} {{ .CardholderName }}
{{ bold "Card Number:" }} {{ .CardNumber }}
{{ bold "Expiry:" }} {{ .ExpiryDate }}
{{ bold "CVV:" }} {{ .CVV }}
{{- if .PIN }}
{{ bold "PIN:" }} {{ .PIN }}
{{- end }}
{{- if .BankName }}
{{ bold "Bank:" }} {{ .BankName }}
{{- end }}
{{- if .Notes }}
{{ bold "Notes:" }} {{ .Notes }}
{{- end }}

{{ bold "Created:" }} {{ formatTime .CreatedAt }}
{{ bold "Updated:" }} {{ formatTime .UpdatedAt }}
{{ bold "Sync Status:" }} {{ syncIcon .SyncStatus }} {{ .SyncStatus }}
`

const binaryTemplate = `
{{ bold "Binary File:" }} {{ cyan .Name }}
{{ bold "ID:" }} {{ .ID }}
{{ bold "Filename:" }} {{ .Filename }}
{{ bold "MIME Type:" }} {{ .MimeType }}
{{ bold "Size:" }} {{ .Size }} bytes
{{- if .Notes }}
{{ bold "Notes:" }} {{ .Notes }}
{{- end }}

{{ bold "Created:" }} {{ formatTime .CreatedAt }}
{{ bold "Updated:" }} {{ formatTime .UpdatedAt }}
{{ bold "Sync Status:" }} {{ syncIcon .SyncStatus }} {{ .SyncStatus }}
`
