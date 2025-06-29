package utils

import (
	"errors"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(userID string) (string, error) {
	jwtSecret := GetSecretKeyFromEnv()
	expiration := constants.AppConfig.DefaultJWTExpiration
	now := time.Now()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func VerifyJWT(tokenString string) (string, time.Time, error) {
	token, err := jwt.Parse(tokenString, jwtSecretKeyFunc)
	if err != nil || !token.Valid {
		return "", time.Time{}, err
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

	// Validate iat (issued at) claim
	iat, ok := claims["iat"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("iat (issued at) not found in token")
	}
	issuedAt := time.Unix(int64(iat), 0)
	if issuedAt.After(now) {
		return "", time.Time{}, errors.New("token used before issued")
	}

	// Validate nbf (not before) claim
	nbf, ok := claims["nbf"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("nbf (not before) not found in token")
	}
	notBefore := time.Unix(int64(nbf), 0)
	if now.Before(notBefore) {
		return "", time.Time{}, errors.New("token used before valid")
	}

	// Validate exp (expiration) claim
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

func jwtSecretKeyFunc(token *jwt.Token) (interface{}, error) {
	jwtSecret := GetSecretKeyFromEnv()
	if token.Method != jwt.SigningMethodHS256 {
		return nil, errors.New("unexpected signing method: only HS256 is allowed")
	}
	return jwtSecret, nil
}
