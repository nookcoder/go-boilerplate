package v4jwt

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
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
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message": "internal server error in jwt"}`))
	}

}