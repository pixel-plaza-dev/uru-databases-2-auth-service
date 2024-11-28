package validator

import (
	mongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	commongrpcvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/validator"
)

type (
	// Validator is the default validator for the auth service gRPC methods
	Validator struct {
		authDatabase *mongodbauth.Database
		validator    commongrpcvalidator.Validator
	}
)

// NewValidator creates a new validator
func NewValidator(
	authDatabase *mongodbauth.Database,
	validator commongrpcvalidator.Validator,
) *Validator {
	return &Validator{authDatabase: authDatabase, validator: validator}
}
