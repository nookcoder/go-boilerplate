package v4jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type Validator[T jwt.Claims] struct {
	*Config
}

func NewValidator[T jwt.Claims](config *Config) *Validator[T] {
	return &Validator[T]{
		Config: config,
	}
}

func (v *Validator[T]) ValidateToken(tokenString string, claims T) (T, error) {
	var empty T
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }
        return v.Config.secretKey, nil
    })
    
    if err != nil { 
        return empty, err 
    }   

    return token.Claims.(T), nil
}