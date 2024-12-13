package validator

import (
	appmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	commonflag "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/flag"
	commongrpcvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/validator"
	commonvalidationsfields "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/utils/validator/fields"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/auth"
	"google.golang.org/grpc/codes"
)

type (
	// Validator is the default validator for the auth service gRPC methods
	Validator struct {
		authDatabase *appmongodbauth.Database
		validator    commongrpcvalidator.Validator
	}
)

// Fields to validate for each gRPC method
var (
	LogInRequestFieldsToValidate, _ = commonvalidationsfields.CreateGRPCStructFieldsToValidate(
		pbauth.LogInRequest{},
		commonflag.Mode,
	)
	IsAccessTokenValidRequestFieldsToValidate, _ = commonvalidationsfields.CreateGRPCStructFieldsToValidate(
		pbauth.IsAccessTokenValidRequest{},
		commonflag.Mode,
	)
	IsRefreshTokenValidRequestFieldsToValidate, _ = commonvalidationsfields.CreateGRPCStructFieldsToValidate(
		pbauth.IsRefreshTokenValidRequest{},
		commonflag.Mode,
	)
	RevokeRefreshTokenRequestFieldsToValidate, _ = commonvalidationsfields.CreateGRPCStructFieldsToValidate(
		pbauth.RevokeRefreshTokenRequest{},
		commonflag.Mode,
	)
	GetRefreshTokenInformationRequestFieldsToValidate, _ = commonvalidationsfields.CreateGRPCStructFieldsToValidate(
		pbauth.GetRefreshTokenInformationRequest{},
		commonflag.Mode,
	)
)

// NewValidator creates a new validator
func NewValidator(
	authDatabase *appmongodbauth.Database,
	validator commongrpcvalidator.Validator,
) (*Validator, error) {
	// Check if either the auth database or the validator is nil
	if authDatabase == nil {
		return nil, appmongodbauth.NilDatabaseError
	}
	if validator == nil {
		return nil, commongrpcvalidator.NilValidatorError
	}

	return &Validator{authDatabase: authDatabase, validator: validator}, nil
}

// ValidateLogInRequest validates a log in request
func (v *Validator) ValidateLogInRequest(request *pbauth.LogInRequest) error {
	// Get validations from fields to validate
	validations, _ := v.validator.ValidateNilFields(
		request,
		LogInRequestFieldsToValidate,
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateIsAccessTokenValidRequest validates an is access token valid request
func (v *Validator) ValidateIsAccessTokenValidRequest(request *pbauth.IsAccessTokenValidRequest) error {
	// Get validations from fields to validate
	validations, _ := v.validator.ValidateNilFields(
		request,
		IsAccessTokenValidRequestFieldsToValidate,
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateIsRefreshTokenValidRequest validates an is refresh token valid request
func (v *Validator) ValidateIsRefreshTokenValidRequest(request *pbauth.IsRefreshTokenValidRequest) error {
	// Get validations from fields to validate
	validations, _ := v.validator.ValidateNilFields(
		request,
		IsRefreshTokenValidRequestFieldsToValidate,
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateRevokeRefreshTokenRequest validates a revoke refresh token request
func (v *Validator) ValidateRevokeRefreshTokenRequest(request *pbauth.RevokeRefreshTokenRequest) error {
	// Get validations from fields to validate
	validations, _ := v.validator.ValidateNilFields(
		request,
		RevokeRefreshTokenRequestFieldsToValidate,
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}

// ValidateGetRefreshTokenInformationRequest validates a get refresh token information request
func (v *Validator) ValidateGetRefreshTokenInformationRequest(request *pbauth.GetRefreshTokenInformationRequest) error {
	// Get validations from fields to validate
	validations, _ := v.validator.ValidateNilFields(
		request,
		GetRefreshTokenInformationRequestFieldsToValidate,
	)

	return v.validator.CheckValidations(validations, codes.InvalidArgument)
}
