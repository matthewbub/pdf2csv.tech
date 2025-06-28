package utils

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bus.zcauldron.com/pkg/constants"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db     *sql.DB
	doOnce sync.Once
)

// GetDB returns a singleton database connection
func GetDB() *sql.DB {
	doOnce.Do(func() {
		db = initDB()
		if db == nil {
			log.Fatal("Failed to initialize the database.")
		}
	})
	return db
}

func initDB() *sql.DB {
	env := GetEnv()
	logger := GetLogger()

	var dbPath string
	var dbSource string

	switch env {
	case constants.ENV_PRODUCTION:
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("Error getting current working directory:", err)
		}
		dbPath = filepath.Join(cwd, "pkg", "database", "prod.db")
		dbSource = dbPath
	case constants.ENV_STAGING:
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("Error getting current working directory:", err)
		}
		dbPath = filepath.Join(cwd, "pkg", "database", "staging.db")
		dbSource = dbPath
	case constants.ENV_DEVELOPMENT:
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("Error getting current working directory:", err)
		}
		dbPath = filepath.Join(cwd, "pkg", "database", "dev.db")
		dbSource = dbPath
	case constants.ENV_TEST:
		// Use in-memory database for tests with a shared cache
		// This ensures all connections use the same in-memory database
		dbSource = "file::memory:?cache=shared&mode=rwc"
		logger.Printf("Using in-memory database for tests")
	default:
		logger.Fatalf("An unrecognized environment was detected. Aborting.")
		panic("An unrecognized environment was detected. Aborting.")
	}

	// For file-based databases, check if the file exists
	if env != constants.ENV_TEST {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			logger.Fatalf("Database file does not exist at path: %s", dbPath)
			return nil
		}
	}

	db, err := sql.Open("sqlite3", dbSource)
	if err != nil {
		logger.Fatalf("Error opening database: %v", err)
		return nil
	}

	// Test the database connection
	if err := db.Ping(); err != nil {
		logger.Fatalf("Failed to ping database: %v", err)
		return nil
	}

	// Configure the connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	logger.Printf("Database connection established successfully (env: %s)", env)
	return db
}
