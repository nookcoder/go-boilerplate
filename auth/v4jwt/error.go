package v4jwt

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

/**
* golang-jwt 에서 제공하는 Error Constant 와 동일한 값을 사용
* App 에서 생성한 jwt 패키지만 사용하기 위해 동일한 값을 사용
* 필요한 상수는 추가해서 사용
* 참고 : https://pkg.go.dev/github.com/golang-jwt/jwt/v5#pkg-constants
 */

 var (
	ErrInvalidKey                = jwt.ErrInvalidKey
	ErrInvalidKeyType            = jwt.ErrInvalidKeyType
	ErrHashUnavailable           = jwt.ErrHashUnavailable
	ErrTokenMalformed            = jwt.ErrTokenMalformed
	ErrTokenUnverifiable         = jwt.ErrTokenUnverifiable
	ErrTokenSignatureInvalid     = jwt.ErrTokenSignatureInvalid
	ErrTokenInvalidAudience      = jwt.ErrTokenInvalidAudience
	ErrTokenExpired              = jwt.ErrTokenExpired
	ErrTokenUsedBeforeIssued     = jwt.ErrTokenUsedBeforeIssued
	ErrTokenInvalidIssuer        = jwt.ErrTokenInvalidIssuer
	ErrTokenNotValidYet          = jwt.ErrTokenNotValidYet
	ErrTokenInvalidId            = jwt.ErrTokenInvalidId
	ErrTokenInvalidClaims        = jwt.ErrTokenInvalidClaims
)

var (
	ErrNotECPublicKey  = jwt.ErrNotECPublicKey
	ErrNotECPrivateKey = jwt.ErrNotECPrivateKey
)

var (
	ErrNotEdPrivateKey = jwt.ErrNotEdPrivateKey
	ErrNotEdPublicKey  = jwt.ErrNotEdPublicKey
)

var (
	ErrJwtMissing = errors.New("missing jwt token")
)

type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error) 

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch { 
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message": "invalid token signature"}`))
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message": "token is expired or not valid yet"}`))
	case errors.Is(err, jwt.ErrTokenMalformed):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message": "invalid token format"}`))
	case errors.Is(err, ErrJwtMissing):
		w.WriteHeader(http.StatusBadGateway) 
		_, _ = w.Write([]byte(`{"message": "missing jwt token"}`))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message": "internal server error in jwt"}`))
	}

}