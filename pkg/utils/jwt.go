package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
)

type JWTKeyManager struct {
	mu           sync.RWMutex
	currentKey   []byte
	previousKeys [][]byte
	keyID        string
}

var keyManager *JWTKeyManager
var keyManagerOnce sync.Once

func generateKeyID(key []byte) string {
	hash := sha256.Sum256(key)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%d_%s", timestamp, hex.EncodeToString(hash[:8]))
}

func getKeyManager() *JWTKeyManager {
	keyManagerOnce.Do(func() {
		currentKey := GetSecretKeyFromEnv()
		keyManager = &JWTKeyManager{
			currentKey:   currentKey,
			previousKeys: make([][]byte, 0),
			keyID:        generateKeyID(currentKey),
		}
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
	for _, key := range km.previousKeys {
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		keys = append(keys, keyCopy)
	}

	return keys
}

func (km *JWTKeyManager) RotateKey(newKey []byte) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if len(newKey) == 0 {
		panic("new key cannot be empty")
	}

	currentKeyCopy := make([]byte, len(km.currentKey))
	copy(currentKeyCopy, km.currentKey)
	km.previousKeys = append(km.previousKeys, currentKeyCopy)

	newKeyCopy := make([]byte, len(newKey))
	copy(newKeyCopy, newKey)
	km.currentKey = newKeyCopy
	km.keyID = generateKeyID(newKeyCopy)

	if len(km.previousKeys) > 3 {
		km.previousKeys = km.previousKeys[1:]
	}
}

func GenerateJWT(userID string) (string, error) {
	km := getKeyManager()
	jwtSecret := km.GetCurrentKey()
	expiration := constants.AppConfig.DefaultJWTExpiration
	now := time.Now()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiration).Unix(),
		"kid":     km.keyID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func VerifyJWT(tokenString string) (string, time.Time, error) {
	km := getKeyManager()
	validKeys := km.GetAllValidKeys()

	var lastErr error
	for _, key := range validKeys {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method: only HS256 is allowed")
			}
			return key, nil
		})

		if err != nil {
			lastErr = err
			continue
		}

		if !token.Valid {
			lastErr = errors.New("token is invalid")
			continue
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			lastErr = errors.New("could not parse claims")
			continue
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			lastErr = errors.New("user_id not found in token")
			continue
		}

		now := time.Now()

		iat, ok := claims["iat"].(float64)
		if !ok {
			lastErr = errors.New("iat (issued at) not found in token")
			continue
		}
		issuedAt := time.Unix(int64(iat), 0)
		if issuedAt.After(now) {
			lastErr = errors.New("token used before issued")
			continue
		}

		nbf, ok := claims["nbf"].(float64)
		if !ok {
			lastErr = errors.New("nbf (not before) not found in token")
			continue
		}
		notBefore := time.Unix(int64(nbf), 0)
		if now.Before(notBefore) {
			lastErr = errors.New("token used before valid")
			continue
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			lastErr = errors.New("expiration not found in token")
			continue
		}
		expirationTime := time.Unix(int64(exp), 0)
		if now.After(expirationTime) {
			lastErr = errors.New("token expired")
			continue
		}

		return userID, expirationTime, nil
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
func RotateJWTKey(newKey []byte) {
	km := getKeyManager()
	km.RotateKey(newKey)
}
