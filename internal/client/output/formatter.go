package output

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Formatter defines the interface for output formatting
type Formatter interface {
	// Format takes data and returns a formatted string
	Format(data interface{}) (string, error)
	// FormatList takes a slice of data and returns a formatted string
	FormatList(data interface{}) (string, error)
}

// NewFormatter creates a formatter based on the format type
func NewFormatter(format string) (Formatter, error) {
	switch format {
	case "text":
		return NewTextFormatter(), nil
	case "json":
		return NewJSONFormatter(), nil
	case "yaml":
		return NewYAMLFormatter(), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (supported: text, json, yaml)", format)
	}
}

// JSONFormatter formats data as JSON
type JSONFormatter struct{}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// Format formats a single item as JSON
func (f *JSONFormatter) Format(data interface{}) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(bytes), nil
}

// FormatList formats a list as JSON
func (f *JSONFormatter) FormatList(data interface{}) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(bytes), nil
}

// YAMLFormatter formats data as YAML
type YAMLFormatter struct{}

// NewYAMLFormatter creates a new YAML formatter
func NewYAMLFormatter() *YAMLFormatter {
	return &YAMLFormatter{}
}

// Format formats a single item as YAML
func (f *YAMLFormatter) Format(data interface{}) (string, error) {
	bytes, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(bytes), nil
}

// FormatList formats a list as YAML
func (f *YAMLFormatter) FormatList(data interface{}) (string, error) {
	bytes, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(bytes), nil
}
