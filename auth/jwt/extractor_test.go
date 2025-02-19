package jwt

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractTokenFromBearerString(t *testing.T) {
	testCases := []struct {
		name      string
		request   *http.Request
		wantToken string
		wantError string
	}{
		{
			name:    "empty / no header",
			request: &http.Request{},
		},
		{
			name: "token in header",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer i-am-a-token"},
				},
			},
			wantToken: "i-am-a-token",
		},
		{
			name: "no bearer",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"i-am-a-token"},
				},
			},
			wantError: "invalid authorization header format",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gotToken, err := extractTokenFromBearerString(testCase.request.Header.Get("Authorization"))
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.wantToken, gotToken)
		})
	}
}

func Test_extractTokenFromCookie(t *testing.T) {
	testCases := []struct {
		name      string
		cookie    *http.Cookie
		wantToken string
		wantError string
	}{
		{
			name:      "no cookie",
			cookie:    nil,
			wantToken: "",
		},
		{
			name:      "cookie has a token",
			cookie:    &http.Cookie{Name: "token", Value: "i-am-a-token"},
			wantToken: "i-am-a-token",
		},
		{
			name:      "cookie has no token",
			cookie:    &http.Cookie{Name: "token"},
			wantToken: "",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)

			if testCase.cookie != nil {
				request.AddCookie(testCase.cookie)
			}

			gotToken, err := extractTokenFromCookie("token")(request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.wantToken, gotToken)
		})
	}
}