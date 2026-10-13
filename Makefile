# Load .env if present, otherwise fall back to .env.example so a fresh clone just works.
ENV_FILE := $(if $(wildcard .env),.env,.env.example)
include $(ENV_FILE)
export

SQLC_VERSION  := v1.31.1
GOOSE_VERSION := v3.28.0
AIR_VERSION   := v1.67.4
NODEMON_VERSION := 3.1.11

.PHONY: help up down run dev nodemon build migrate migrate-down migrate-status migrate-create sqlc test vet tidy lint-api

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

up: ## Start the auth Postgres
	docker compose up -d

down: ## Stop the auth Postgres
	docker compose down

run: ## Run the auth service
	go run ./cmd/api

dev: ## Run the auth service with hot reload (Air)
	go run github.com/air-verse/air@$(AIR_VERSION)

nodemon: ## Run with auto-restart using nodemon (needs Node.js; config in nodemon.json)
	npx --yes nodemon@$(NODEMON_VERSION)

build: ## Build the auth service binary into ./bin
	go build -o bin/martgo-auth ./cmd/api

migrate: ## Apply all migrations (includes the admin seed)
	go run ./cmd/migration up

migrate-down: ## Roll back the last migration
	go run ./cmd/migration down

migrate-status: ## Show migration status
	go run ./cmd/migration status

migrate-create: ## New SQL migration: make migrate-create name=add_something
	go run github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION) -dir migrations -s create $(name) sql

sqlc: ## Generate type-safe query code into internal/db
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

test: ## Run unit tests
	go test -race -count=1 ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy go.mod
	go mod tidy

lint-api: ## Validate the OpenAPI spec
	npx --yes @redocly/cli@latest lint api/openapi.yaml
