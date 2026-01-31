package errors

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/repository"
)

// DomainError represents a domain-specific error with additional context.
type DomainError struct {
	Code    ErrorCode
	Message string
	Err     error
}

// ErrorCode represents different types of domain errors.
type ErrorCode string

const (
	// CodeInvalidInput indicates invalid user input.
	CodeInvalidInput ErrorCode = "INVALID_INPUT"

	// CodeNotFound indicates a resource was not found.
	CodeNotFound ErrorCode = "NOT_FOUND"

	// CodeAlreadyExists indicates a resource already exists.
	CodeAlreadyExists ErrorCode = "ALREADY_EXISTS"

	// CodeUnauthorized indicates authentication failure.
	CodeUnauthorized ErrorCode = "UNAUTHORIZED"

	// CodeForbidden indicates permission denied.
	CodeForbidden ErrorCode = "FORBIDDEN"

	// CodeConflict indicates a version or state conflict.
	CodeConflict ErrorCode = "CONFLICT"

	// CodeInternal indicates an internal server error.
	CodeInternal ErrorCode = "INTERNAL"

	// CodeUnavailable indicates a service is unavailable.
	CodeUnavailable ErrorCode = "UNAVAILABLE"
)

// Error implements the error interface.
func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error.
func (e *DomainError) Unwrap() error {
	return e.Err
}

// NewInvalidInput creates a new invalid input error.
func NewInvalidInput(message string) *DomainError {
	return &DomainError{
		Code:    CodeInvalidInput,
		Message: message,
	}
}

// NewNotFound creates a new not found error.
func NewNotFound(message string) *DomainError {
	return &DomainError{
		Code:    CodeNotFound,
		Message: message,
	}
}

// NewAlreadyExists creates a new already exists error.
func NewAlreadyExists(message string) *DomainError {
	return &DomainError{
		Code:    CodeAlreadyExists,
		Message: message,
	}
}

// NewUnauthorized creates a new unauthorized error.
func NewUnauthorized(message string) *DomainError {
	return &DomainError{
		Code:    CodeUnauthorized,
		Message: message,
	}
}

// NewForbidden creates a new forbidden error.
func NewForbidden(message string) *DomainError {
	return &DomainError{
		Code:    CodeForbidden,
		Message: message,
	}
}

// NewConflict creates a new conflict error.
func NewConflict(message string) *DomainError {
	return &DomainError{
		Code:    CodeConflict,
		Message: message,
	}
}

// NewInternal creates a new internal error.
func NewInternal(message string, err error) *DomainError {
	return &DomainError{
		Code:    CodeInternal,
		Message: message,
		Err:     err,
	}
}

// Wrap wraps an error with additional context.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// ToGRPCStatus converts a domain error to a gRPC status error.
// It also handles repository errors and generic errors.
func ToGRPCStatus(err error) error {
	if err == nil {
		return nil
	}

	// Handle DomainError
	var domainErr *DomainError
	if errors.As(err, &domainErr) {
		return status.Error(domainErrorToGRPCCode(domainErr.Code), domainErr.Message) //nolint:wrapcheck // gRPC status error is the correct format
	}

	// Handle repository errors
	if errors.Is(err, repository.ErrNotFound) {
		return status.Error(codes.NotFound, "resource not found") //nolint:wrapcheck // gRPC status error is the correct format
	}

	if errors.Is(err, repository.ErrDuplicate) {
		return status.Error(codes.AlreadyExists, "resource already exists") //nolint:wrapcheck // gRPC status error is the correct format
	}

	if errors.Is(err, repository.ErrVersionConflict) {
		return status.Error(codes.Aborted, "version conflict") //nolint:wrapcheck // gRPC status error is the correct format
	}

	// Default to internal error
	return status.Error(codes.Internal, "internal server error") //nolint:wrapcheck // gRPC status error is the correct format
}

// domainErrorToGRPCCode maps domain error codes to gRPC status codes.
func domainErrorToGRPCCode(code ErrorCode) codes.Code {
	switch code {
	case CodeInvalidInput:
		return codes.InvalidArgument
	case CodeNotFound:
		return codes.NotFound
	case CodeAlreadyExists:
		return codes.AlreadyExists
	case CodeUnauthorized:
		return codes.Unauthenticated
	case CodeForbidden:
		return codes.PermissionDenied
	case CodeConflict:
		return codes.Aborted
	case CodeUnavailable:
		return codes.Unavailable
	case CodeInternal:
		return codes.Internal
	default:
		return codes.Unknown
	}
}

// ToGRPCStatusWithDetails converts an error to gRPC status with formatted details.
func ToGRPCStatusWithDetails(err error, details string) error {
	if err == nil {
		return nil
	}

	var domainErr *DomainError
	if errors.As(err, &domainErr) {
		message := domainErr.Message
		if details != "" {
			message = fmt.Sprintf("%s: %s", message, details)
		}

		return status.Error(domainErrorToGRPCCode(domainErr.Code), message) //nolint:wrapcheck // gRPC status error is the correct format
	}

	return ToGRPCStatus(err)
}
