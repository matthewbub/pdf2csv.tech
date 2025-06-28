package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type LoginAttempt struct {
	Count     int
	LastTry   time.Time
	LockedUntil time.Time
}

var (
	loginAttempts = make(map[string]*LoginAttempt)
	attemptsMu    sync.RWMutex
)

const (
	MaxLoginAttempts = 5
	LockoutDuration  = 15 * time.Minute
	AttemptWindow    = 5 * time.Minute
)

func BruteForceProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		// In test mode, prefer X-Forwarded-For header if available
		if gin.Mode() == gin.TestMode {
			if forwardedIP := c.GetHeader("X-Forwarded-For"); forwardedIP != "" {
				ip = forwardedIP
			}
		}
		
		// Check if IP is locked out (read-only operation)
		attemptsMu.RLock()
		attempt, exists := loginAttempts[ip]
		now := time.Now()
		

		
		if exists && now.Before(attempt.LockedUntil) {
			remaining := attempt.LockedUntil.Sub(now)
			attemptsMu.RUnlock()
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Account temporarily locked due to too many failed attempts",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			c.Abort()
			return
		}
		attemptsMu.RUnlock()
		
		// If not locked out, proceed with request
		c.Next()
	}
}

func RecordFailedLogin(ip string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	
	attempt, exists := loginAttempts[ip]
	now := time.Now()
	
	if !exists {
		loginAttempts[ip] = &LoginAttempt{
			Count:   1,
			LastTry: now,
		}
		return
	}
	
	// Reset if window expired
	if now.Sub(attempt.LastTry) > AttemptWindow {
		attempt.Count = 1
	} else {
		attempt.Count++
	}
	
	attempt.LastTry = now
	
	// Lock account if max attempts reached
	if attempt.Count >= MaxLoginAttempts {
		attempt.LockedUntil = now.Add(LockoutDuration)
	}
}

func RecordSuccessfulLogin(ip string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	
	delete(loginAttempts, ip)
}

func GetLoginAttempts(ip string) *LoginAttempt {
	attemptsMu.RLock()
	defer attemptsMu.RUnlock()
	
	if attempt, exists := loginAttempts[ip]; exists {
		return &LoginAttempt{
			Count:       attempt.Count,
			LastTry:     attempt.LastTry,
			LockedUntil: attempt.LockedUntil,
		}
	}
	return nil
}

func ClearLoginAttempts() {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	
	loginAttempts = make(map[string]*LoginAttempt)
}

func ClearLoginAttemptsForIP(ip string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	
	delete(loginAttempts, ip)
}