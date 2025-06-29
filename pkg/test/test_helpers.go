package test

import (
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"sync"
)

var (
	TestConfig = struct {
		PrimaryUser    string
		PrimaryEmail   string
		SecondaryUser  string
		SecondaryEmail string
		Password       string
	}{
		PrimaryUser:    "testuser1",
		PrimaryEmail:   "test1@example.com",
		SecondaryUser:  "testuser2",
		SecondaryEmail: "test2@example.com",
		Password:       "Password123!", // Nobody should use this password in production
	}

	userCounter = 3
	userMutex   sync.Mutex
)

func GetNextUser() (string, string, error) {
	userMutex.Lock()
	defer userMutex.Unlock()

	username := fmt.Sprintf("testuser%d", userCounter)
	email := fmt.Sprintf("testuser%d@example.com", userCounter)
	userCounter++

	return username, email, nil
}
func GetPrimaryUser() (string, string) {
	userMutex.Lock()
	defer userMutex.Unlock()
	return TestConfig.PrimaryUser, TestConfig.PrimaryEmail
}

func GetSecondaryUser() (string, string) {
	userMutex.Lock()
	defer userMutex.Unlock()
	return TestConfig.SecondaryUser, TestConfig.SecondaryEmail
}
