package v4jwt

import (
	"errors"
	"net/http"
	"strings"
)

// Extractor: 토큰을 추출하는 함수 타입
// 만약 헤더나 토큰이 빈 문자열인 경우 에러로 인식하지 않고 nil 반환
type Extractor func(r *http.Request) (string, error) 

// AuthHeaderExtractor: Authorization: Bearer <token> 에서 token 추출 
func AuthHeaderExtractor(r *http.Request) (string, error) { 
	authHeader := r.Header.Get("Authorization") 
	if authHeader == "" {
		return "", nil 
	}

	authHeaderParts := strings.Split(authHeader, " ") 
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	} 

	return authHeaderParts[1], nil
}

// CookieExtractor: 쿠키에서 토큰 추출
func CookieExtractor(cookieName string) Extractor {
	return func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(cookieName)
		// 쿠키가 없는 경우 빈 문자열 반환
		if err != nil {
			return "", nil
		}

		return cookie.Value, nil 
	}
}