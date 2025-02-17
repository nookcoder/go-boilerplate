package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestCreateToken(t *testing.T) {
	t.Run("should create token successfully with claims", func(t *testing.T) {
		var tokenString string
		var claims jwt.Claims = jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{"test"},  // Note: Audience is now a string slice
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			ID:        "test",                    // Note: Id is now ID
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   "test",
		}

		tokenString, err := CreateTokenWithClaims(claims)
		assert.NoError(t, err)
		assert.NotNil(t, tokenString)
		assert.IsType(t, "string", tokenString)
		assert.NotEmpty(t, tokenString)

		// t.Logf("token: %s", tokenString)
	})

	t.Run("should parse token successfully", func(t *testing.T) {
		tokenString, err := createNewTestToken() 
		if err != nil {
			t.Fatalf("failed to create new test token: %v", err)
		}

		claims, err := ParseToken(tokenString) 
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		assert.NotNil(t, claims)
		regClaims, ok := claims.(*jwt.RegisteredClaims)
		assert.True(t, ok)

		t.Run("should have valid claims", func(t *testing.T) {
			assert.Equal(t, "test", regClaims.Audience[0])
			assert.Equal(t, "test", regClaims.Issuer)
			assert.Equal(t, "test", regClaims.Subject)
			assert.Equal(t, "test", regClaims.ID)
		})

		t.Run("should have invalid claims", func(t *testing.T) {
			assert.NotEqual(t, "test1", regClaims.Audience[0])
			assert.NotEqual(t, "test1", regClaims.Issuer)
			assert.NotEqual(t, "test1", regClaims.Subject)
			assert.NotEqual(t, "test1", regClaims.ID)
		})
	})

	t.Run("should parse token successfully with custom claims", func(t *testing.T) {
		tokenString, err := createNewTestTokenWithCustomClaims()
		if err != nil {
			t.Fatalf("failed to create new test token: %v", err)
		}

		claims, err := ParseTokenWithAppClaims(tokenString)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		assert.NotNil(t, claims)
		assert.IsType(t, &CustomClaims{}, claims)

		t.Run("should have valid claims", func(t *testing.T) {
			assert.Equal(t, "user_id_test", claims.UserId)
			// assert.Equal(t, "test", claims.Audience[0])
			assert.Equal(t, "test", claims.Issuer)
			assert.Equal(t, "test", claims.Subject)
			assert.Equal(t, "test", claims.ID)
		})

		t.Run("should have invalid claims", func(t *testing.T) {
			assert.NotEqual(t, "user_id_test_no", claims.UserId) 
		})
	})

	t.Run("test token error", func(t *testing.T) {
		t.Run("malformed token test", func(t *testing.T) {
			tokenString := "invalid_token.format" 
			claims, err := ParseToken(tokenString) 
			assert.Error(t, err) 
			assert.Nil(t, claims) 
			assert.Equal(t, "token is malformed", err.Error())
		})

		t.Run("expired token test", func(t *testing.T) {
			var claims jwt.Claims = jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{"test"},  // Note: Audience is now a string slice
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 1)), // 토큰의 만료 시간
				ID:        "test",                    // Note: Id is now ID
				IssuedAt:  jwt.NewNumericDate(time.Now()), // 토큰이 발급된 시간
				Issuer:    "test",
				NotBefore: jwt.NewNumericDate(time.Now()), // 토큰이 유효한 시간
				Subject:   "test", // 토큰의 주체(사용자 또는 자격 증명)	
			}
			tokenString, err := CreateTokenWithClaims(claims) 
			if err != nil { 
				t.Fatalf("failed to create new test token: %v", err)
			}

			time.Sleep(time.Second * 2)

			claim, err := ParseToken(tokenString)
			assert.Error(t, err) 
			assert.Nil(t, claim) 
			assert.Equal(t, "token is expired or not valid yet", err.Error())
		})

		t.Run("invalid token test", func(t *testing.T) {
			wrongKey := []byte("wrong_key") 
			claims := CustomClaims{
				UserId: "test",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, _ := token.SignedString(wrongKey)
	
			claim, err := ParseTokenWithAppClaims(tokenString)
			assert.Error(t, err)
			assert.Nil(t, claim)
			assert.Equal(t, "token signature is invalid", err.Error())
		})
	})
}

func createNewTestToken() (string, error) {
	var claims jwt.Claims = jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"test"},  // Note: Audience is now a string slice
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		ID:        "test",                    // Note: Id is now ID
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "test",
		NotBefore: jwt.NewNumericDate(time.Now()),
		Subject:   "test",
	}

	tokenString, err := CreateTokenWithClaims(claims)
	return tokenString, err
}

func createNewTestTokenWithCustomClaims() (string, error) {
	claims := &CustomClaims{
		UserId: "user_id_test",		
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			Subject:   "test",
			Audience:  jwt.ClaimStrings{"test"},
			ID:        "test",
		},
	}

	tokenString, err := CreateTokenWithClaims(claims)
	return tokenString, err
}
