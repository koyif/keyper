package repository

import "errors"

var (
	// ErrNotFound is returned when a requested entity is not found.
	ErrNotFound = errors.New("entity not found")

	// ErrVersionConflict is returned when an optimistic lock fails due to version mismatch.
	ErrVersionConflict = errors.New("version conflict: entity was modified by another process")

	// ErrDuplicate is returned when attempting to create an entity that already exists.
	ErrDuplicate = errors.New("entity already exists")
)
