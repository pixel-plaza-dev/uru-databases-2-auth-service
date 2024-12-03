package validator

import (
	mongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	commongrpcvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/validator"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/auth"
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

// ValidateIsAccessTokenValidRequest validates an is access token valid request
func (v Validator) ValidateIsAccessTokenValidRequest(request *pbauth.IsAccessTokenValidRequest) error {
	// Get validations from fields to validate
	validations := v.validator.ValidateNonEmptyStringFields(
		request,
		&map[string]string{
			"JwtId": "jwt_id",
		},
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateIsRefreshTokenValidRequest validates an is refresh token valid request
func (v Validator) ValidateIsRefreshTokenValidRequest(request *pbauth.IsRefreshTokenValidRequest) error {
	// Get validations from fields to validate
	validations := v.validator.ValidateNonEmptyStringFields(
		request,
		&map[string]string{
			"JwtId": "jwt_id",
		},
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateRevokeRefreshTokenRequest validates a revoke refresh token request
func (v Validator) ValidateRevokeRefreshTokenRequest(request *pbauth.RevokeRefreshTokenRequest) error {
	// Get validations from fields to validate
	validations := v.validator.ValidateNonEmptyStringFields(
		request,
		&map[string]string{
			"JwtId": "jwt_id",
		},
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateGetRefreshTokenInformationRequest validates a get refresh token information request
func (v Validator) ValidateGetRefreshTokenInformationRequest(request *pbauth.GetRefreshTokenInformationRequest) error {
	// Get validations from fields to validate
	validations := v.validator.ValidateNonEmptyStringFields(
		request,
		&map[string]string{
			"JwtId": "jwt_id",
		},
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}
