package grpc

import (
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb/database/auth"
)

type (
	// TokenValidator interface
	TokenValidator interface {
		IsTokenValid(tokenString string, isRefreshToken bool) bool
	}

	// DefaultTokenValidator struct
	DefaultTokenValidator struct {
		authDatabase *auth.Database
	}
)

// NewDefaultTokenValidator creates a new default token validator
func NewDefaultTokenValidator(
	authDatabase *auth.Database,
) *DefaultTokenValidator {
	return &DefaultTokenValidator{
		authDatabase: authDatabase,
	}
}

// IsTokenValid checks if the token is valid
func (d *DefaultTokenValidator) IsTokenValid(
	tokenString string,
	isRefreshToken bool,
) bool {
	// Validate the token
	if isRefreshToken {
		// Check if the refresh token is valid
		isValid, err := d.authDatabase.IsRefreshTokenValid(tokenString)
		if err != nil {
			return false
		}
		return isValid

	}

	// Check if the access token is valid
	isValid, err := d.authDatabase.IsAccessTokenValid(tokenString)
	if err != nil {
		return false
	}
	return isValid
}
