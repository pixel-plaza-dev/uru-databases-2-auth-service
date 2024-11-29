package validator

import (
	mongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	commongrpcvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/validator"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/auth"
	"google.golang.org/grpc/codes"
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

// ValidateLogInRequest validates a log in request
func (v Validator) ValidateLogInRequest(request *pbauth.LogInRequest) error {
	// Get validations from fields to validate
	validations := v.validator.ValidateNonEmptyStringFields(
		request,
		&map[string]string{
			"Password": "password",
			"Username": "username",
		},
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}
