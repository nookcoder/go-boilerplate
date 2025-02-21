package v4jwt

import "github.com/golang-jwt/jwt/v4"

type TokenCreator interface {
	CreateToken(claims jwt.Claims) (string, error)
}

type TokenValidator[T jwt.Claims] interface {
	ValidateToken(tokenString string, claims T) (T, error)
}

type Manager[T jwt.Claims] interface { 
	TokenCreator 
	TokenValidator[T]
}

// TokenManager: 토큰 생성과 검증을 관리하는 구조체
type TokenManager[T jwt.Claims] struct {
	Creator TokenCreator
	Validator TokenValidator[T]
}

func NewTokenManager[T jwt.Claims](creator TokenCreator, validator TokenValidator[T]) Manager[T] {
	return &TokenManager[T]{
		Creator: creator,
		Validator: validator,
	}
}

func (m *TokenManager[T]) CreateToken(claims jwt.Claims) (string, error) {
	return m.Creator.CreateToken(claims)
}

func (m *TokenManager[T]) ValidateToken(tokenString string, claims T) (T, error) {
	return m.Validator.ValidateToken(tokenString, claims)
}

