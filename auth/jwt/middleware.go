package jwt

import (
	"context"
	"net/http"
)

// Jwt 토큰 검증 및 Context 에 클레임 저장
// 요구사항에 따라서 Error 핸들링 부분 수정
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authorization 헤더에서 토큰 추출 
		// 만약 Bearer 를 사용하지 않으면 새로운 Extractor 를 생성해서 사용 
		authHeader := r.Header.Get("Authorization")
		token, err := extractTokenFromBearerString(authHeader)

		if err != nil { 
			// Header is Empty || Invalid Format
			http.Error(w, "Unauthorized: " + err.Error(), http.StatusUnauthorized)
			return
		}

		// 토큰 검증 및 클레임 파싱 
		// 클레임 파싱 시 커스텀 클레임을 사용하는 경우 ParseTokenWithAppClaims 사용  
		claims, err := ParseToken(token)

		if err != nil { 
			// 토큰 검증 실패 
			http.Error(w, "Unauthorized: " + err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user", claims) 
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}