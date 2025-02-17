package jwt

import (
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