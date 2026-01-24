.PHONY: proto proto-clean test test-crypto build-server build-client run-server clean help db-up db-down db-reset migrate-up migrate-down migrate-create migrate-status

# Directories
PROTO_DIR := pkg/api/proto
PROTO_OUT_DIR := pkg/api/proto
OPENAPI_OUT_DIR := api/openapi

# Proto files
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

# Go binary locations (add GOPATH/bin to PATH if not already)
PROTOC := protoc
PROTOC_GEN_GO := $(shell go env GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(shell go env GOPATH)/bin/protoc-gen-go-grpc
PROTOC_GEN_GRPC_GATEWAY := $(shell go env GOPATH)/bin/protoc-gen-grpc-gateway
PROTOC_GEN_OPENAPIV2 := $(shell go env GOPATH)/bin/protoc-gen-openapiv2

# Include paths for googleapis
GOOGLEAPIS_DIR := third_party

# Database configuration
DB_HOST := localhost
DB_PORT := 5432
DB_USER := keyper
DB_PASSWORD := keyper_dev_password
DB_NAME := keyper
DB_SSL_MODE := disable
MIGRATIONS_DIR := migrations
DATABASE_URL := postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSL_MODE)

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

proto: ## Generate Go code and OpenAPI spec from proto files
	@echo "Generating protobuf code..."
	@mkdir -p $(OPENAPI_OUT_DIR)
	@for proto in $(PROTO_FILES); do \
		echo "Processing $$proto"; \
		$(PROTOC) \
			--proto_path=$(PROTO_DIR) \
			--proto_path=$(GOOGLEAPIS_DIR) \
			--go_out=$(PROTO_OUT_DIR) \
			--go_opt=paths=source_relative \
			--go-grpc_out=$(PROTO_OUT_DIR) \
			--go-grpc_opt=paths=source_relative \
			--grpc-gateway_out=$(PROTO_OUT_DIR) \
			--grpc-gateway_opt=paths=source_relative \
			--grpc-gateway_opt=generate_unbound_methods=true \
			--openapiv2_out=$(OPENAPI_OUT_DIR) \
			--openapiv2_opt=allow_merge=true,merge_file_name=keyper \
			$$proto; \
	done
	@echo "Protobuf code generation complete!"

proto-clean: ## Remove generated proto files
	@echo "Cleaning generated proto files..."
	@find $(PROTO_OUT_DIR) -name "*.pb.go" -type f -delete
	@find $(PROTO_OUT_DIR) -name "*_grpc.pb.go" -type f -delete
	@find $(PROTO_OUT_DIR) -name "*.pb.gw.go" -type f -delete
	@rm -rf $(OPENAPI_OUT_DIR)
	@echo "Cleanup complete!"

test: ## Run all tests
	@echo "Running all tests..."
	@go test -v ./...

test-crypto: ## Run crypto package tests
	@echo "Running crypto tests..."
	@go test -v ./internal/crypto/

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

build-server: ## Build the gRPC server binary
	@echo "Building server..."
	@go build -o bin/keyper-server ./cmd/server

build-client: ## Build the CLI client binary
	@echo "Building client..."
	@go build -o bin/keyper-client ./cmd/client

build: build-server build-client ## Build both server and client

run-server: ## Run the gRPC server
	@echo "Starting server..."
	@go run ./cmd/server

clean: proto-clean ## Clean all generated files and binaries
	@echo "Cleaning binaries..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "Clean complete!"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

install-tools: ## Install required protoc plugins
	@echo "Installing protoc plugins..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	@go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
	@echo "Tools installed successfully!"

db-up: ## Start PostgreSQL database using Docker Compose
	@echo "Starting database..."
	@cd deployment/docker && docker compose up -d postgres
	@echo "Waiting for database to be healthy..."
	@sleep 5
	@echo "Database is ready!"

db-down: ## Stop PostgreSQL database
	@echo "Stopping database..."
	@cd deployment/docker && docker compose down

db-reset: db-down db-up ## Reset database (stop and start)

migrate-status: ## Show current migration version
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version

migrate-up: ## Run all up migrations (auto-run on server start)
	@echo "Running migrations..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up
	@echo "Migrations completed!"

migrate-down: ## Rollback last migration
	@echo "Rolling back migration..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1
	@echo "Rollback completed!"

migrate-create: ## Create a new migration (usage: make migrate-create NAME=migration_name)
	@if [ -z "$(NAME)" ]; then \
		echo "Error: NAME is required. Usage: make migrate-create NAME=migration_name"; \
		exit 1; \
	fi
	@migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(NAME)
	@echo "Migration files created!"

.DEFAULT_GOAL := help
