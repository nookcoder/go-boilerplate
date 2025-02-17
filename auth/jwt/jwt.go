package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

/**
* Jwt Boilerplate 작성을 위한 인터페이스
* 필요한 경우 사용
 */
type Jwt interface {
	CreateToken() (string, error)
	CreateTokenWithClaims(claims jwt.Claims) (string, error)
	ParseToken(tokenString string) (jwt.Claims, error)
}

/**
* 커스텀 클레임 타입
* 필요한 경우 사용
*/
type CustomClaims struct {
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

// key 변수는 Boilerplate 작성을 위한 예제 값입니다.
// Signing key 와 Verifying key 는 안전하게 관리해주시기 바랍니다.
var (
	key []byte = []byte("sample-key")
	t *jwt.Token
	s string 
)


/** 
* 기본 토큰 생성 함수 
*/
func CreateToken() (string, error) {
	t = jwt.New(jwt.SigningMethodHS256) // 원하는 Signing Method 를 선택 
	return t.SignedString(key)
}

/**
* 클레임을 포함한 토큰 생성 함수 
*/
func CreateTokenWithClaims(claims jwt.Claims) (string, error) {
	t = jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // 원하는 Signing Method 선택 
	return t.SignedString(key)
}

/**
* 토큰 파싱 함수 
*/
func ParseToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { // 
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil { 
		return nil, handleJwtError(token, err)
	}

	return token.Claims, nil
}

/**
* 커스텀 클레임을 포함한 토큰 파싱 함수 
*/
func ParseTokenWithAppClaims(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token)(interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, handleJwtError(token, err)
	}

	return token.Claims.(*CustomClaims), nil
}