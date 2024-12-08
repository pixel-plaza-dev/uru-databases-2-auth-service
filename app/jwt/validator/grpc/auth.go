package grpc

import (
	"context"
	appmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	commonredisauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/redis/auth"
)

type (
	// DefaultTokenValidator struct
	DefaultTokenValidator struct {
		authDatabase        *appmongodbauth.Database
		redisTokenValidator commonredisauth.TokenValidator
	}
)

// NewDefaultTokenValidator creates a new default token validator
func NewDefaultTokenValidator(
	authDatabase *appmongodbauth.Database,
	redisTokenValidator commonredisauth.TokenValidator,
) (*DefaultTokenValidator, error) {
	// Check if the auth database is nil
	if authDatabase == nil {
		return nil, appmongodbauth.NilDatabaseError
	}

	return &DefaultTokenValidator{
		authDatabase:        authDatabase,
		redisTokenValidator: redisTokenValidator,
	}, nil
}

// IsTokenValid checks if the token is valid
func (d *DefaultTokenValidator) IsTokenValid(
	token string, jwtId string, isRefreshToken bool,
) (bool, error) {
	// Check if Redis is enabled
	if d.redisTokenValidator != nil {
		// Check if the token is in the Redis cache
		return d.redisTokenValidator.IsTokenValid(jwtId)
	}

	// Validate the token
	if isRefreshToken {
		// Check if the refresh token is valid
		isValid, err := d.authDatabase.IsRefreshTokenValid(context.Background(), jwtId)
		if err != nil {
			return false, err
		}
		return isValid, nil
	}

	// Check if the access token is valid
	isValid, err := d.authDatabase.IsAccessTokenValid(context.Background(), jwtId)
	if err != nil {
		return false, err
	}
	return isValid, nil
}
