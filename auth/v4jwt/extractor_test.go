package v4jwt

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthHeaderExtractor(t *testing.T) {
	testCases := []struct { 
		name string 
		request *http.Request 
		expectedToken string 
		expectedError string 
	} {
		{
			name: "Header에 Authorization 헤더가 없는 경우",
			request: &http.Request{},
			expectedToken: "",
			expectedError: "",
		},
		{
			name: "Authorization 헤더가 Bearer 형식이 아닌 경우",
			request: &http.Request{
				Header: map[string][]string{
					"Authorization": {"Bearer"},
				},
			},
			expectedToken: "",
			expectedError: "Authorization header format must be Bearer {token}",
		},
		{

			name: "Authorization 헤더가 있고 Bearer 형식이며 토큰이 있는 경우",
			request: &http.Request{
				Header: map[string][]string{
					"Authorization": {"Bearer token"},
				},
			},
			expectedToken: "token",
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc 
			t.Parallel()
			token, err := AuthHeaderExtractor(tc.request)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				assert.Empty(t, token)
			} else { 
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedToken, token)
		})
	}
}

func TestCookieExtractor(t *testing.T) {
	testCases := []struct {
		name      string
		cookie    *http.Cookie
		wantToken string
		wantError string
	}{
		{
			name:      "쿠키가 없는 경우",
			cookie:    nil,
			wantToken: "",
		},
		{
			name:      "쿠키에 값이 있는 경우",
			cookie:    &http.Cookie{Name: "token", Value: "i-am-a-token"},
			wantToken: "i-am-a-token",
		},
		{
			name:      "쿠키에 값이 없는 경우",
			cookie:    &http.Cookie{Name: "token"},
			wantToken: "",
		},
	}	

	for _, tc := range testCases {
		tc := tc 
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() 
			request, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			require.NoError(t, err)

			if tc.cookie != nil {
				request.AddCookie(tc.cookie)
			}

			token, err := CookieExtractor("token")(request)
			assert.Equal(t, tc.wantToken, token)
			assert.NoError(t, err)
		})
	}
}