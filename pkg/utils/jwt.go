package utils

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type keyWithID struct {
	key   []byte
	keyID string
}

type JWTKeyManager struct {
	mu           sync.RWMutex
	currentKey   []byte
	previousKeys []keyWithID
	keyID        string
	keyIDToKey   map[string][]byte
}

var keyManager *JWTKeyManager
var keyManagerOnce sync.Once

func generateKeyID(key []byte) string {
	hash := sha256.Sum256(key)
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%d_%s", timestamp, hex.EncodeToString(hash[:8]))
}

func getKeyManager() *JWTKeyManager {
	keyManagerOnce.Do(func() {
		currentKey := GetSecretKeyFromEnv()
		keyID := generateKeyID(currentKey)
		keyManager = &JWTKeyManager{
			currentKey:   currentKey,
			previousKeys: make([]keyWithID, 0),
			keyID:        keyID,
			keyIDToKey:   make(map[string][]byte),
		} // Store the current key in the mapping
		keyManager.keyIDToKey[keyID] = make([]byte, len(currentKey))
		copy(keyManager.keyIDToKey[keyID], currentKey)
	})
	return keyManager
}

func (km *JWTKeyManager) GetCurrentKey() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Create a defensive copy to prevent external modification
	keyCopy := make([]byte, len(km.currentKey))
	copy(keyCopy, km.currentKey)
	return keyCopy
}

func (km *JWTKeyManager) GetAllValidKeys() [][]byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([][]byte, 0, len(km.previousKeys)+1)

	// Create a copy of the current key
	currentKeyCopy := make([]byte, len(km.currentKey))
	copy(currentKeyCopy, km.currentKey)
	keys = append(keys, currentKeyCopy)

	// Create copies of all previous keys
	for _, keyWithID := range km.previousKeys {
		keyCopy := make([]byte, len(keyWithID.key))
		copy(keyCopy, keyWithID.key)
		keys = append(keys, keyCopy)
	}

	return keys
}

func (km *JWTKeyManager) RotateKey(newKey []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if len(newKey) == 0 {
		return errors.New("new key cannot be empty")
	}

	// Check if the new key is the same as current key
	if bytes.Equal(km.currentKey, newKey) {
		return errors.New("new key is identical to current key")
	}

	currentKeyCopy := make([]byte, len(km.currentKey))
	copy(currentKeyCopy, km.currentKey)
	currentKeyWithID := keyWithID{
		key:   currentKeyCopy,
		keyID: km.keyID,
	}
	km.previousKeys = append(km.previousKeys, currentKeyWithID)

	newKeyCopy := make([]byte, len(newKey))
	copy(newKeyCopy, newKey)
	km.currentKey = newKeyCopy
	newKeyID := generateKeyID(newKeyCopy)
	km.keyID = newKeyID

	// Update keyID mapping
	km.keyIDToKey[newKeyID] = make([]byte, len(newKeyCopy))
	copy(km.keyIDToKey[newKeyID], newKeyCopy)

	// Clean up old keys from mapping if we exceed the limit
	if len(km.previousKeys) > 3 {
		oldestKeyID := km.previousKeys[0].keyID
		delete(km.keyIDToKey, oldestKeyID)
		km.previousKeys = km.previousKeys[1:]
	}

	return nil
}

func GenerateJWT(userID string) (string, error) {
	km := getKeyManager()
	jwtSecret := km.GetCurrentKey()

	km.mu.RLock()
	currentKeyID := km.keyID
	km.mu.RUnlock()

	expiration := constants.AppConfig.AccessTokenExpiration
	now := time.Now()
	jti := uuid.New().String()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiration).Unix(),
		"kid":     currentKeyID,
		"type":    "access",
		"jti":     jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func GenerateRefreshToken(userID string) (string, error) {
	km := getKeyManager()
	jwtSecret := km.GetCurrentKey()

	km.mu.RLock()
	currentKeyID := km.keyID
	km.mu.RUnlock()

	expiration := constants.AppConfig.RefreshTokenExpiration
	now := time.Now()
	jti := uuid.New().String()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiration).Unix(),
		"kid":     currentKeyID,
		"type":    "refresh",
		"jti":     jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func GenerateTokenPair(userID string) (accessToken, refreshToken string, err error) {
	accessToken, err = GenerateJWT(userID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func verifyTokenWithKey(tokenString string, key []byte) (string, time.Time, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method: only HS256 is allowed")
		}
		return key, nil
	})

	if err != nil {
		return "", time.Time{}, err
	}

	if !token.Valid {
		return "", time.Time{}, errors.New("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", time.Time{}, errors.New("could not parse claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", time.Time{}, errors.New("user_id not found in token")
	}

	now := time.Now()

	iat, ok := claims["iat"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("iat (issued at) not found in token")
	}
	issuedAt := time.Unix(int64(iat), 0)
	if issuedAt.After(now) {
		return "", time.Time{}, errors.New("token used before issued")
	}

	nbf, ok := claims["nbf"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("nbf (not before) not found in token")
	}
	notBefore := time.Unix(int64(nbf), 0)
	if now.Before(notBefore) {
		return "", time.Time{}, errors.New("token used before valid")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("expiration not found in token")
	}
	expirationTime := time.Unix(int64(exp), 0)
	if now.After(expirationTime) {
		return "", time.Time{}, errors.New("token expired")
	}

	return userID, expirationTime, nil
}

func VerifyRefreshToken(tokenString string) (string, time.Time, error) {
	km := getKeyManager()

	// First, try to parse token to get the kid claim and verify it's a refresh token
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err == nil {
		if claims, ok := unverifiedToken.Claims.(jwt.MapClaims); ok {
			// Check if this is a refresh token
			if tokenType, exists := claims["type"]; exists {
				if typeStr, ok := tokenType.(string); ok && typeStr != "refresh" {
					return "", time.Time{}, errors.New("invalid token type: expected refresh token")
				}
			}

			if kidClaim, exists := claims["kid"]; exists {
				if kidStr, ok := kidClaim.(string); ok {
					// Try to find the specific key first
					km.mu.RLock()
					if specificKey, found := km.keyIDToKey[kidStr]; found {
						km.mu.RUnlock()
						// Try verification with the specific key
						if userID, expTime, err := verifyTokenWithKey(tokenString, specificKey); err == nil {
							return userID, expTime, nil
						}
					} else {
						km.mu.RUnlock()
					}
				}
			}
		}
	}

	// Fallback to trying all keys
	validKeys := km.GetAllValidKeys()

	var lastErr error
	for _, key := range validKeys {
		if userID, expTime, err := verifyTokenWithKey(tokenString, key); err == nil {
			return userID, expTime, nil
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", time.Time{}, lastErr
	}
	return "", time.Time{}, errors.New("no valid key found for refresh token")
}

func VerifyJWT(tokenString string) (string, time.Time, error) {
	km := getKeyManager()

	// First, try to parse token to get the kid claim
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err == nil {
		if claims, ok := unverifiedToken.Claims.(jwt.MapClaims); ok {
			if kidClaim, exists := claims["kid"]; exists {
				if kidStr, ok := kidClaim.(string); ok {
					// Try to find the specific key first
					km.mu.RLock()
					if specificKey, found := km.keyIDToKey[kidStr]; found {
						km.mu.RUnlock()
						// Try verification with the specific key
						if userID, expTime, err := verifyTokenWithKey(tokenString, specificKey); err == nil {
							return userID, expTime, nil
						}
					} else {
						km.mu.RUnlock()
					}
				}
			}
		}
	}

	// Fallback to trying all keys
	validKeys := km.GetAllValidKeys()

	var lastErr error
	for _, key := range validKeys {
		if userID, expTime, err := verifyTokenWithKey(tokenString, key); err == nil {
			return userID, expTime, nil
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", time.Time{}, lastErr
	}
	return "", time.Time{}, errors.New("no valid key found for token")
}

func jwtSecretKeyFunc(token *jwt.Token) (interface{}, error) {
	if token.Method != jwt.SigningMethodHS256 {
		return nil, errors.New("unexpected signing method: only HS256 is allowed")
	}

	km := getKeyManager()
	return km.GetCurrentKey(), nil
}
func RotateJWTKey(newKey []byte) error {
	km := getKeyManager()
	return km.RotateKey(newKey)
}

func BlacklistToken(db *sql.DB, tokenString string, reason string) error {
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("could not parse token claims")
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return errors.New("token does not contain jti claim")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return errors.New("token does not contain user_id claim")
	}

	tokenType, ok := claims["type"].(string)
	if !ok {
		return errors.New("token does not contain type claim")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("token does not contain exp claim")
	}
	expiresAt := time.Unix(int64(exp), 0)

	_, err = db.Exec(`
		INSERT INTO token_blacklist (token_jti, user_id, token_type, expires_at, reason)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(token_jti) DO NOTHING
	`, jti, userID, tokenType, expiresAt, reason)

	if err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	return nil
}

func IsTokenBlacklisted(db *sql.DB, tokenString string) (bool, error) {
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("could not parse token claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return false, errors.New("user_id not found in token")
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		// If no JTI, check for user-level blacklist
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist WHERE user_id = ? AND token_type = 'all'", userID).Scan(&count)
		if err != nil {
			return false, fmt.Errorf("failed to check user blacklist: %w", err)
		}
		return count > 0, nil
	}

	// Check for specific token blacklist or user-level blacklist
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM token_blacklist 
		WHERE token_jti = ? OR (user_id = ? AND token_type = 'all')
	`, jti, userID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return count > 0, nil
}

func CleanupExpiredBlacklistedTokens(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM token_blacklist WHERE expires_at < ?", time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired blacklisted tokens: %w", err)
	}
	return nil
}

func BlacklistAllUserTokens(db *sql.DB, userID string, reason string) error {
	_, err := db.Exec(`
		INSERT INTO token_blacklist (token_jti, user_id, token_type, expires_at, reason)
		SELECT DISTINCT 'user_revoke_' || ? || '_' || datetime('now'), ?, 'all', datetime('now', '+1 year'), ?
		WHERE NOT EXISTS (
			SELECT 1 FROM token_blacklist 
			WHERE user_id = ? AND token_type = 'all'
		)
	`, userID, userID, reason, userID)

	if err != nil {
		return fmt.Errorf("failed to blacklist all user tokens: %w", err)
	}

	return nil
}
