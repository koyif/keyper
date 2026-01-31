package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// customError is a test error type for testing errors.As
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}

// TestErrorWrapping verifies that error chains are properly preserved
// using %w format verb in fmt.Errorf calls.
func TestErrorWrapping(t *testing.T) {
	t.Run("sql.ErrNoRows wrapping preserved", func(t *testing.T) {
		originalErr := sql.ErrNoRows
		wrappedErr := fmt.Errorf("query failed: %w", originalErr)

		if !errors.Is(wrappedErr, sql.ErrNoRows) {
			t.Errorf("errors.Is failed: wrapped error should be identifiable as sql.ErrNoRows")
		}
	})

	t.Run("nested error wrapping preserved", func(t *testing.T) {
		baseErr := sql.ErrConnDone
		level1 := fmt.Errorf("database operation failed: %w", baseErr)
		level2 := fmt.Errorf("repository method failed: %w", level1)

		if !errors.Is(level2, sql.ErrConnDone) {
			t.Errorf("errors.Is failed: nested wrapped error should be identifiable as sql.ErrConnDone")
		}
	})

	t.Run("custom error wrapping preserved", func(t *testing.T) {
		customErr := errors.New("custom error")
		wrappedErr := fmt.Errorf("operation failed: %w", customErr)

		if !errors.Is(wrappedErr, customErr) {
			t.Errorf("errors.Is failed: wrapped custom error should be identifiable")
		}
	})

	t.Run("errors.As works with wrapped errors", func(t *testing.T) {
		baseErr := &customError{msg: "test error"}
		wrappedErr := fmt.Errorf("wrapped: %w", baseErr)

		var ce *customError
		if !errors.As(wrappedErr, &ce) {
			t.Errorf("errors.As failed: should be able to extract custom error type")
		}

		if ce.msg != "test error" {
			t.Errorf("extracted error has wrong message: got %q, want %q", ce.msg, "test error")
		}
	})
}
