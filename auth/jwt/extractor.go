package jwt

import (
	"errors"
	"net/http"
	"strings"
)

type TokenExtractor func(r *http.Request) (string, error)

// Bearer 헤더에서 토큰 추출
func extractTokenFromBearerString(bearerString string) (string, error) {
	if len(bearerString) == 0 {
		return "", nil
	}

	parts := strings.Split(bearerString, " ") 

	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil 
}

// 쿠키에서 토큰 추출 
// 쿠키가 없으면 Jwt 가 없는 것이므로 오류로 인식하지 않음 
func extractTokenFromCookie(cookieString string) TokenExtractor { 
	return func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(cookieString)
		if err == http.ErrNoCookie{
			return "", nil
		}

		return cookie.Value, nil
	}
}
