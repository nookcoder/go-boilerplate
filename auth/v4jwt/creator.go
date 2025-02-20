package v4jwt

import "github.com/golang-jwt/jwt/v4"

type Creator struct {
	*Config 
}

func NewCreator(config *Config) *Creator { 
	return &Creator{ 
		Config: config,
	}
}

func (c *Creator) CreateToken(claims jwt.Claims) (string, error) { 
	if claims != nil { 
		t := jwt.NewWithClaims(c.Config.method, claims) 
		return t.SignedString(c.Config.secretKey)
	}

	t := jwt.New(c.Config.method) 
	return t.SignedString(c.Config.secretKey)
}