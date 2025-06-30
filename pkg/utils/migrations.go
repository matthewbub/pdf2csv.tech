package utils

import (
	"context"
	"fmt"
	"log"
	"os"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/mattn/go-sqlite3"
)

func RunMigrations() error {
	env := GetEnv()
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		switch env {
		case constants.ENV_PRODUCTION:
			dbPath = "sqlite3://pkg/database/prod.db?cache=shared&mode=rwc"
		case constants.ENV_STAGING:
			dbPath = "sqlite3://pkg/database/staging.db?cache=shared&mode=rwc"
		case constants.ENV_DEVELOPMENT:
			dbPath = "sqlite3://pkg/database/dev.db?cache=shared&mode=rwc"
		case constants.ENV_TEST:
			// Use in-memory database for tests with shared cache
			dbPath = "sqlite3://file::memory:?cache=shared&mode=rwc"
		default:
			return fmt.Errorf("invalid environment: %s", env)
		}
	}

	m, err := migrate.New(
		"file://pkg/database/migrations",
		dbPath)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	defer func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil {
			// We can't return these errors since we're in a defer,
			// but we should at least log them
			log.Printf("Error closing migration source: %v", sourceErr)
		}
		if dbErr != nil {
			log.Printf("Error closing migration database: %v", dbErr)
		}
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Migrations completed successfully")

	return nil
}

func RunMigrationsTest() error {
	log.Println("Setting up test database with user history...")
	ctx := context.Background()

	// Get the in-memory database connection
	db := GetDB()
	if db == nil {
		return fmt.Errorf("failed to get database connection for test setup")
	}

	// Since migrations aren't working with in-memory DB, let's manually create the users table
	log.Println("Manually creating users table for tests...")
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			application_environment_role TEXT NOT NULL DEFAULT 'user' CHECK (application_environment_role IN ('admin', 'user')),
			email TEXT NOT NULL UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			security_questions_answered BOOLEAN DEFAULT FALSE,
			inactive_at TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create the active_users view
	log.Println("Creating active_users view...")
	_, err = db.ExecContext(ctx, `
		CREATE VIEW IF NOT EXISTS active_users AS 
		SELECT *,
		       inactive_at IS NULL as is_active 
		FROM users
	`)
	if err != nil {
		return fmt.Errorf("failed to create active_users view: %w", err)
	}

	// Create other essential tables
	log.Println("Creating other essential tables...")
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS security_questions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			question_1 TEXT NOT NULL,
			answer_1 TEXT NOT NULL,
			question_2 TEXT NOT NULL,
			answer_2 TEXT NOT NULL,
			question_3 TEXT NOT NULL,
			answer_3 TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create security_questions table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS transactions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			date TIMESTAMP NOT NULL,
			description TEXT NOT NULL,
			amount TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('credit', 'debit')),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create transactions table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS password_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			password TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create password_history table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			session_token TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS token_blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_jti TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			token_type TEXT NOT NULL CHECK (token_type IN ('access', 'refresh', 'all')),
			expires_at TIMESTAMP NOT NULL,
			blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			reason TEXT DEFAULT 'revoked'
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create token_blacklist table: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_token_blacklist_jti ON token_blacklist(token_jti)
	`)
	if err != nil {
		return fmt.Errorf("failed to create token_blacklist index: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires_at ON token_blacklist(expires_at)
	`)
	if err != nil {
		return fmt.Errorf("failed to create token_blacklist expires_at index: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_preferences (
			user_id INTEGER PRIMARY KEY,
			use_markdown BOOLEAN DEFAULT TRUE,
			color_theme TEXT DEFAULT 'light',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create user_preferences table: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			log.Printf("Rolling back test setup transaction due to error: %v", err)
			tx.Rollback()
			return
		}
		if err = tx.Commit(); err != nil {
			log.Printf("Failed to commit test setup transaction: %v", err)
			err = fmt.Errorf("failed to commit transaction: %w", err)
		} else {
			log.Println("Test database setup completed successfully")
		}
	}()

	// This is a table to track unique user names and emails
	// in the db because we enforce those restrictions at a db level
	// it's not in a migration file because its only used for testing
	log.Println("Creating user_history table for test data...")
	_, err = tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT,
			email TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create test history table: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO user_history (username, email) 
		VALUES (?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	primaryUser := "testuser1"
	primaryEmail := "test1@example.com"
	secondaryUser := "testuser2"
	secondaryEmail := "test2@example.com"

	log.Printf("Inserting primary test user: %s (%s)", primaryUser, primaryEmail)
	_, err = stmt.ExecContext(ctx, primaryUser, primaryEmail)
	if err != nil {
		return fmt.Errorf("failed to insert primary test user: %w", err)
	}

	log.Printf("Inserting secondary test user: %s (%s)", secondaryUser, secondaryEmail)
	_, err = stmt.ExecContext(ctx, secondaryUser, secondaryEmail)
	if err != nil {
		return fmt.Errorf("failed to insert secondary test user: %w", err)
	}

	return nil
}

// DropTestDatabase cleans up test database resources
func DropTestDatabase() error {
	log.Println("Cleaning up test database resources...")

	// For in-memory databases, we just need to close the connection
	// The database will be automatically cleaned up when the connection closes
	db := GetDB()
	if db != nil {
		log.Println("Closing database connection...")
		if err := db.Close(); err != nil {
			log.Printf("Warning: Error closing database connection: %v", err)
			return fmt.Errorf("failed to close test database connection: %w", err)
		}
		log.Println("Test database cleanup completed")
	} else {
		log.Println("No database connection to clean up")
	}

	return nil
}
