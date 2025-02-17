package jwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// 토큰 오류 함수 처리
func handleJwtError(token *jwt.Token, err error) error {
	// jwt.Parse, jwt.ParseWithClaims 에서 토큰 파싱에 실패하는 경우 token 이 nil 이 됨 
	// 1. header.payload.signature 형식이 아닌 경우 
	// 2. 각 부분이 Base64 로 인코딩 되지 않은 경우 
	if token == nil { 
        if errors.Is(err, jwt.ErrTokenMalformed) {
            return errors.New("token is malformed")
        }
        return fmt.Errorf("invalid token: %v", err)
	}

	switch {
	case token.Valid:
		return nil 
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return errors.New("token signature is invalid")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		// Token is expired or not valid yet
		return errors.New("token is expired or not valid yet") 
	default:
		return errors.New("Could not handle this token error")
	}
}