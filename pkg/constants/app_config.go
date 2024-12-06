package constants

import "time"

type Config struct {
	Version           string
	ProductionDomain  string
	StagingDomain     string
	DevelopmentDomain string
	TestDomain        string
	DevelopmentPorts  struct {
		Frontend int
		Backend  int

		// The staging port runs both the frontend and backend
		// in local dev, you have both servers running in isolation, and visit Config.DevelopmentPorts.Frontend to see the UI; & HTTP requests are made to Config.DevelopmentPorts.Backend
		// In staging, you have both servers running together, and visit Config.StagingPort to see the UI; HTTP requests are made to Config.StagingPort as well
		StagingPort int
	}
	DefaultJWTExpiration time.Duration
	// TODO: Implement ExtendJWTExpiration
	// ExtendJWTExpiration  time.Duration

	// TODO: Implement SecondaryAuthType
	// SecondaryAuthType string
}

var AppConfig = Config{
	Version:           "0.0.1",
	ProductionDomain:  "zcauldron.com",
	StagingDomain:     "localhost",
	DevelopmentDomain: "localhost",
	TestDomain:        "localhost",
	DevelopmentPorts: struct {
		Frontend    int
		Backend     int
		StagingPort int
	}{
		Frontend:    3001,
		Backend:     8080,
		StagingPort: 8080,
	},
	DefaultJWTExpiration: time.Minute * 30,

	// TODO: Implement ExtendJWTExpiration
	// ExtendJWTExpiration:  time.Hour * 24,

	// TODO: Implement SecondaryAuthType
	// SecondaryAuthType: "KBA", // KBA = Knowledge Based Authentication || MFA = Multi-Factor Authentication
}
