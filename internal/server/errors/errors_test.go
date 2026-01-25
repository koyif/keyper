package errors

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestDomainError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *DomainError
		want string
	}{
		{
			name: "error without wrapped error",
			err: &DomainError{
				Code:    CodeNotFound,
				Message: "user not found",
			},
			want: "[NOT_FOUND] user not found",
		},
		{
			name: "error with wrapped error",
			err: &DomainError{
				Code:    CodeInternal,
				Message: "database error",
				Err:     errors.New("connection failed"),
			},
			want: "[INTERNAL] database error: connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("DomainError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	domainErr := &DomainError{
		Code:    CodeInternal,
		Message: "wrapped error",
		Err:     innerErr,
	}

	unwrapped := domainErr.Unwrap()
	if !errors.Is(unwrapped, innerErr) {
		t.Errorf("Unwrap() did not return the wrapped error")
	}
}

func TestNewErrorFunctions(t *testing.T) {
	tests := []struct {
		name     string
		create   func() *DomainError
		wantCode ErrorCode
	}{
		{
			name:     "NewInvalidInput",
			create:   func() *DomainError { return NewInvalidInput("invalid") },
			wantCode: CodeInvalidInput,
		},
		{
			name:     "NewNotFound",
			create:   func() *DomainError { return NewNotFound("not found") },
			wantCode: CodeNotFound,
		},
		{
			name:     "NewAlreadyExists",
			create:   func() *DomainError { return NewAlreadyExists("exists") },
			wantCode: CodeAlreadyExists,
		},
		{
			name:     "NewUnauthorized",
			create:   func() *DomainError { return NewUnauthorized("unauthorized") },
			wantCode: CodeUnauthorized,
		},
		{
			name:     "NewForbidden",
			create:   func() *DomainError { return NewForbidden("forbidden") },
			wantCode: CodeForbidden,
		},
		{
			name:     "NewConflict",
			create:   func() *DomainError { return NewConflict("conflict") },
			wantCode: CodeConflict,
		},
		{
			name:     "NewInternal",
			create:   func() *DomainError { return NewInternal("internal", errors.New("err")) },
			wantCode: CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.create()
			if err.Code != tt.wantCode {
				t.Errorf("Error code = %v, want %v", err.Code, tt.wantCode)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
		want    string
	}{
		{
			name:    "wrap nil error",
			err:     nil,
			message: "context",
			want:    "",
		},
		{
			name:    "wrap existing error",
			err:     errors.New("original"),
			message: "context",
			want:    "context: original",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := Wrap(tt.err, tt.message)
			if tt.want == "" {
				if wrapped != nil {
					t.Errorf("Wrap(nil) = %v, want nil", wrapped)
				}
			} else {
				if wrapped == nil {
					t.Error("Wrap() returned nil, want non-nil")
				} else if wrapped.Error() != tt.want {
					t.Errorf("Wrap() = %v, want %v", wrapped.Error(), tt.want)
				}
			}
		})
	}
}

func TestToGRPCStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "nil error",
			err:      nil,
			wantCode: codes.OK,
		},
		{
			name:     "domain error - invalid input",
			err:      NewInvalidInput("invalid field"),
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "domain error - not found",
			err:      NewNotFound("resource not found"),
			wantCode: codes.NotFound,
		},
		{
			name:     "domain error - already exists",
			err:      NewAlreadyExists("duplicate entry"),
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "domain error - unauthorized",
			err:      NewUnauthorized("not authenticated"),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "domain error - forbidden",
			err:      NewForbidden("permission denied"),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "domain error - conflict",
			err:      NewConflict("version conflict"),
			wantCode: codes.Aborted,
		},
		{
			name:     "repository error - not found",
			err:      repository.ErrNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "repository error - duplicate",
			err:      repository.ErrDuplicate,
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "repository error - version conflict",
			err:      repository.ErrVersionConflict,
			wantCode: codes.Aborted,
		},
		{
			name:     "generic error",
			err:      errors.New("unknown error"),
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := ToGRPCStatus(tt.err)

			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("ToGRPCStatus(nil) = %v, want nil", grpcErr)
				}
				return
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatal("ToGRPCStatus() did not return a gRPC status error")
			}

			if st.Code() != tt.wantCode {
				t.Errorf("ToGRPCStatus() code = %v, want %v", st.Code(), tt.wantCode)
			}
		})
	}
}

func TestToGRPCStatusWithDetails(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		details     string
		wantCode    codes.Code
		wantMessage string
	}{
		{
			name:        "domain error with details",
			err:         NewNotFound("user not found"),
			details:     "user_id: 123",
			wantCode:    codes.NotFound,
			wantMessage: "user not found: user_id: 123",
		},
		{
			name:        "domain error without details",
			err:         NewInvalidInput("invalid input"),
			details:     "",
			wantCode:    codes.InvalidArgument,
			wantMessage: "invalid input",
		},
		{
			name:        "repository error",
			err:         repository.ErrNotFound,
			details:     "some detail",
			wantCode:    codes.NotFound,
			wantMessage: "resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := ToGRPCStatusWithDetails(tt.err, tt.details)

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatal("ToGRPCStatusWithDetails() did not return a gRPC status error")
			}

			if st.Code() != tt.wantCode {
				t.Errorf("ToGRPCStatusWithDetails() code = %v, want %v", st.Code(), tt.wantCode)
			}

			if st.Message() != tt.wantMessage {
				t.Errorf("ToGRPCStatusWithDetails() message = %v, want %v", st.Message(), tt.wantMessage)
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that errors.As and errors.Is work correctly with domain errors
	originalErr := errors.New("original error")
	domainErr := NewInternal("internal error", originalErr)

	// Test errors.As
	var targetErr *DomainError
	if !errors.As(domainErr, &targetErr) {
		t.Error("errors.As() failed to unwrap DomainError")
	}

	// Test errors.Is with wrapped error
	wrappedErr := fmt.Errorf("wrapped: %w", domainErr)
	if !errors.As(wrappedErr, &targetErr) {
		t.Error("errors.As() failed to unwrap through multiple layers")
	}
}
