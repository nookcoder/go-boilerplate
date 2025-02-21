package v4jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

var testCases = []struct {
	name          string
	claims        *validateTestClaims
	manager       Manager[*validateTestClaims]
	expectedError error
}{
	{
		name: "유효한 토큰",
		claims: &validateTestClaims{
			UserId: "123",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer:    "test",
				Subject:   "test",
			},
		},
		manager: NewTokenManager[*validateTestClaims](
			NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
		),
		expectedError: nil,
	},
	{
		name: "서명 키가 다른 경우",
		claims: &validateTestClaims{
			UserId: "123",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		},
		manager: NewTokenManager[*validateTestClaims](
			NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("wrong_secret"))),
			NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
		),
		expectedError: jwt.ErrTokenSignatureInvalid,
	},
	{
		name: "Claims가 유효하지 않은 경우",
		claims: &validateTestClaims{
			UserId: "", // 빈 UserId
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		},
		manager: NewTokenManager[*validateTestClaims](
			NewCreator(NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
			NewValidator[*validateTestClaims](NewConfig(jwt.SigningMethodHS256, []byte("secret"))),
		),
		expectedError: errors.New("user_id is required"),
	},
}

func TestTokenManager(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	// jwt 패키지의 타임라인 조정
	jwt.TimeFunc = func() time.Time {
		return baseTime
	}
	defer func() {
		jwt.TimeFunc = time.Now
	}()

	t.Parallel()
	
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// 토큰 생성
			token, err := tc.manager.CreateToken(tc.claims)
			require.NoError(t, err)

			// 토큰 검증
			validatedClaims, err := tc.manager.ValidateToken(token, tc.claims)
			
			if tc.expectedError != nil {
				if tc.name == "Claims가 유효하지 않은 경우" {
					require.Error(t, err)
					require.EqualError(t, err, tc.expectedError.Error())
				} else {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.expectedError)
				}
				return
			}

			// 성공 케이스 검증
			require.NoError(t, err)
			require.Equal(t, tc.claims.UserId, validatedClaims.UserId)
			require.Equal(t, tc.claims.ExpiresAt, validatedClaims.ExpiresAt)
			require.Equal(t, tc.claims.IssuedAt, validatedClaims.IssuedAt)
			require.Equal(t, tc.claims.NotBefore, validatedClaims.NotBefore)
			require.Equal(t, tc.claims.Issuer, validatedClaims.Issuer)
			require.Equal(t, tc.claims.Subject, validatedClaims.Subject)
		})
	}
}