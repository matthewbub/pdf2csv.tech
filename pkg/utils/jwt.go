package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
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

	expiration := constants.AppConfig.DefaultJWTExpiration
	now := time.Now()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiration).Unix(),
		"kid":     currentKeyID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
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
