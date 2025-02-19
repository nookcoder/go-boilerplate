package jwt

import (
	"errors"
	"strings"
)

// Bearer 헤더에서 토큰 추출
func extractTokenFromBearerString(bearerString string) (string, error) {
	if len(bearerString) == 0 {
		return "", errors.New("authorization header is empty")
	}

	parts := strings.Split(bearerString, " ") 

	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil 
}