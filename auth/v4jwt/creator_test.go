package v4jwt

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

type testClaims struct { 
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

func (c *testClaims) Valid() error { 
	if err := c.RegisteredClaims.Valid(); err != nil { 
		return err 
	}

	if c.UserId == "" { 
		return errors.New("user_id is required")
	}

	return nil 
}

func TestCreateToken(t *testing.T) {
	t.Run("토큰 생성 성공", func(t *testing.T) {
		creator := NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret")))	
		claims := &testClaims{
			UserId: "123",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
				IssuedAt: jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer: "test",
				Subject: "test",
			},
		}

		token ,err := creator.CreateToken(claims)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		fmt.Print(token)
	})
}
