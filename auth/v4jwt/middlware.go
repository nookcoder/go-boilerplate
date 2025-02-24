package v4jwt

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

type ContextKey struct {}  

type JwtMiddleware struct {
	extractor Extractor 
	validator *Validator[jwt.Claims]
	errorHandler ErrorHandler
	claims jwt.Claims
}

func NewJwtMiddleware(extractor Extractor, validator *Validator[jwt.Claims], errorHandler ErrorHandler, claims jwt.Claims) *JwtMiddleware {
	return &JwtMiddleware{
		extractor: extractor,
		validator: validator,
		errorHandler: DefaultErrorHandler,
		claims: claims,
	}
}

func (m *JwtMiddleware) CheckJwt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS 요청은 통과 
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r) 
			return 
		}

		tokenString, err := m.extractor(r)
		if err != nil { 
			m.errorHandler(w, r, err) 
			return 
		}

		if tokenString == "" {
			m.errorHandler(w, r, ErrJwtMissing)
			return 
		}

		claims, err := m.validator.ValidateToken(tokenString, m.claims)
		if err != nil {
			m.errorHandler(w, r, err)
			return 
		}

		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, claims))
		next.ServeHTTP(w, r)
	})
}