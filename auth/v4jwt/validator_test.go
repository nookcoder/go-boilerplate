package v4jwt

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type validateTestClaims struct { 
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

func (c *validateTestClaims) Valid() error { 
	if err := c.RegisteredClaims.Valid(); err != nil { 
		return err 
	}

	if c.UserId == "" { 
		return errors.New("user_id is required")
	}

	return nil 
}

func TestValidateToken(t *testing.T) {
	testCases := []struct { 
		name string 
		testClaims *validateTestClaims
		creator *Creator 
		validator *Validator[*validateTestClaims]
		expectedError error 
	}{
		{
			name: "유효한 토큰",
			testClaims: &validateTestClaims{
				UserId: "123",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
					IssuedAt: jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer: "test",
					Subject: "test",
				},
			},
			creator: NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			validator: NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			expectedError: nil,
		},
		{
			name: "키가 다른 경우",
			testClaims: &validateTestClaims{
				UserId: "123",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
					IssuedAt: jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer: "test",
					Subject: "test",
				},
			},
			creator: NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("invalid_secret"))),
			validator: NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			expectedError: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "토큰이 만료된 경우",
			testClaims: &validateTestClaims{
				UserId: "123",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute * 5)),
					IssuedAt: jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer: "test",
					Subject: "test",
				},
			},
			creator: NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			validator: NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			expectedError: jwt.ErrTokenExpired,
		},
		{
			name: "토큰의 유효시간이 되지 않은 경우",
			testClaims: &validateTestClaims{
				UserId: "123",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
					IssuedAt: jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
					Issuer: "test",
					Subject: "test",
				},
			},
			creator: NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			validator: NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			expectedError: jwt.ErrTokenNotValidYet,
		},
		{
			name: "Claims가 유효하지 않은 경우",
			testClaims: &validateTestClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
					IssuedAt: jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer: "test",
					Subject: "test",
				},
			},	
			creator: NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			validator: NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			expectedError: errors.New("user_id is required"),
		},
	}

	t.Parallel()
	for _, tc := range testCases {
		tc := tc 
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.creator.CreateToken(tc.testClaims)
			require.NoError(t, err) 

			claims, err := tc.validator.ValidateToken(token, tc.testClaims)
			if err != nil && tc.expectedError != nil {
				if tc.name == "Claims가 유효하지 않은 경우" {
                    assert.EqualError(t, err, tc.expectedError.Error())
					fmt.Println(err.Error())
					return
                }
				assert.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
				return 
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.testClaims.UserId, claims.UserId)
		})

	}
}