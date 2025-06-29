package utils

import (
	"errors"
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

func getKeyManager() *JWTKeyManager {
	keyManagerOnce.Do(func() {
		keyManager = &JWTKeyManager{
			currentKey:   GetSecretKeyFromEnv(),
			previousKeys: make([][]byte, 0),
			keyID:        "current",
		}
	})
	return keyManager
}

func (km *JWTKeyManager) GetCurrentKey() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKey
}

func (km *JWTKeyManager) GetAllValidKeys() [][]byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([][]byte, 0, len(km.previousKeys)+1)
	keys = append(keys, km.currentKey)
	keys = append(keys, km.previousKeys...)
	return keys
}

func (km *JWTKeyManager) RotateKey(newKey []byte) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.previousKeys = append(km.previousKeys, km.currentKey)
	km.currentKey = newKey

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
