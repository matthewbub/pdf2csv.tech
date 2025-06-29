# AGENT Guide

## Build & Test Commands

- Frontend (routes/): cd routes && pnpm dev, pnpm build, pnpm typecheck
- Backend (Go): go run main.go, go build, go test ./..., go test -run TestSignUpEndpoint
- Database migrations auto-run via utils.RunMigrations()

## Code Style Guidelines

### Go

- gofmt with tabs; import standard, third-party, local packages
- error handling: check errors, log.Println(), response.Success()/response.Error()
- naming: PascalCase exports, camelCase locals; use prepared statements & defer rollback

### TypeScript (routes/)

- strict mode; React FCs with hooks; import React, third-party, then @/\*; state via Zustand selectors; styling via Tailwind CSS; props via explicit interfaces; UI errors use bg-red-50 text-red-700

### Python (lib/pdf_service)

DEPRECATED DO NOT USE OR LOOKUP

## Agent Rules

- Cursor rules: none detected
- Copilot instructions: none detected
