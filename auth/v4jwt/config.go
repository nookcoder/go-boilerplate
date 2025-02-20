package v4jwt

import "github.com/golang-jwt/jwt/v4"

type Config struct {
	method jwt.SigningMethod
	secretKey []byte 
}

func NewConfig(method jwt.SigningMethod, secretKey []byte) *Config { 
	return &Config{ 
		method: method,
		secretKey: secretKey,
	}
}