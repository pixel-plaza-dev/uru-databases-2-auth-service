package auth

import (
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb/database/auth"
	commonjwtissuer "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/issuer"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/user"
	"golang.org/x/net/context"
)

// Server is the gRPC auth server
type Server struct {
	authDatabase *auth.Database
	userClient   pbuser.UserClient
	jwtIssuer    commonjwtissuer.Issuer
	logger       Logger
	pbauth.UnimplementedAuthServer
}

// NewServer creates a new gRPC auth server
func NewServer(
	authDatabase *auth.Database,
	userClient pbuser.UserClient,
	jwtIssuer commonjwtissuer.Issuer,
	logger Logger,
) *Server {
	return &Server{
		authDatabase: authDatabase,
		userClient:   userClient,
		jwtIssuer:    jwtIssuer,
		logger:       logger,
	}
}

// LogIn logs in a user
func (s Server) LogIn(
	ctx context.Context,
	request *pbauth.LogInRequest,
) (*pbauth.LogInResponse, error) {
	/*
		// Validation variables
		validations := make(map[string][]error)

		// Get the request fields
		fieldsToValidate := map[string]string{
			"Username": "username",
			"Password": "password",
		}

		// Check if the required string fields are empty
		commonvalidator.ValidNonEmptyStringFields(
			&validations,
			request,
			&fieldsToValidate,
		)

		return nil, nil
	*/
	return nil, InDevelopmentError
}

// IsAccessTokenValid checks if an access token is valid
func (s Server) IsAccessTokenValid(
	ctx context.Context,
	request *pbauth.IsAccessTokenValidRequest,
) (*pbauth.IsAccessTokenValidResponse, error) {
	return nil, InDevelopmentError
}

// IsRefreshTokenValid checks if a refresh token is valid
func (s Server) IsRefreshTokenValid(
	ctx context.Context,
	request *pbauth.IsRefreshTokenValidRequest,
) (*pbauth.IsRefreshTokenValidResponse, error) {
	return nil, InDevelopmentError
}

// RefreshToken refreshes a token
func (s Server) RefreshToken(
	ctx context.Context,
	request *pbauth.RefreshTokenRequest,
) (*pbauth.RefreshTokenResponse, error) {
	return nil, InDevelopmentError
}

// LogOut logs out a user
func (s Server) LogOut(
	ctx context.Context,
	request *pbauth.LogOutRequest,
) (*pbauth.LogOutResponse, error) {
	return nil, InDevelopmentError
}

// GetSessions gets user' sessions
func (s Server) GetSessions(
	ctx context.Context,
	request *pbauth.GetSessionsRequest,
) (*pbauth.GetSessionsResponse, error) {
	return nil, InDevelopmentError
}

// CloseSession closes a user' session
func (s Server) CloseSession(
	ctx context.Context,
	request *pbauth.CloseSessionRequest,
) (*pbauth.CloseSessionResponse, error) {
	return nil, InDevelopmentError
}

// CloseSessions closes user' sessions
func (s Server) CloseSessions(
	ctx context.Context,
	request *pbauth.CloseSessionsRequest,
) (*pbauth.CloseSessionsResponse, error) {
	return nil, InDevelopmentError
}

// AddPermission adds a permission
func (s Server) AddPermission(
	ctx context.Context,
	request *pbauth.AddPermissionRequest,
) (*pbauth.AddPermissionResponse, error) {
	return nil, InDevelopmentError
}

// RevokePermission revokes a permission
func (s Server) RevokePermission(
	ctx context.Context,
	request *pbauth.RevokePermissionRequest,
) (*pbauth.RevokePermissionResponse, error) {
	return nil, InDevelopmentError
}

// GetPermission gets a given permission
func (s Server) GetPermission(
	ctx context.Context,
	request *pbauth.GetPermissionRequest,
) (*pbauth.GetPermissionResponse, error) {
	return nil, InDevelopmentError
}

// GetPermissions gets all the permissions
func (s Server) GetPermissions(
	ctx context.Context,
	request *pbauth.GetPermissionsRequest,
) (*pbauth.GetPermissionsResponse, error) {
	return nil, InDevelopmentError
}

// AddRolePermission adds a permission to a role
func (s Server) AddRolePermission(
	ctx context.Context,
	request *pbauth.AddRolePermissionRequest,
) (*pbauth.AddRolePermissionResponse, error) {
	return nil, InDevelopmentError
}

// RevokeRolePermission revokes a permission from a role
func (s Server) RevokeRolePermission(
	ctx context.Context,
	request *pbauth.RevokeRolePermissionRequest,
) (*pbauth.RevokeRolePermissionResponse, error) {
	return nil, InDevelopmentError
}

// GetRolePermissions gets all the permissions of a role
func (s Server) GetRolePermissions(
	ctx context.Context,
	request *pbauth.GetRolePermissionsRequest,
) (*pbauth.GetRolePermissionsResponse, error) {
	return nil, InDevelopmentError
}

// AddRole adds a role
func (s Server) AddRole(
	ctx context.Context,
	request *pbauth.AddRoleRequest,
) (*pbauth.AddRoleResponse, error) {
	return nil, InDevelopmentError
}

// RevokeRole revokes a role
func (s Server) RevokeRole(
	ctx context.Context,
	request *pbauth.RevokeRoleRequest,
) (*pbauth.RevokeRoleResponse, error) {
	return nil, InDevelopmentError
}

// GetRoles gets all the roles
func (s Server) GetRoles(
	ctx context.Context,
	request *pbauth.GetRolesRequest,
) (*pbauth.GetRolesResponse, error) {
	return nil, InDevelopmentError
}

// AddUserRole adds a role to a user
func (s Server) AddUserRole(
	ctx context.Context,
	request *pbauth.AddUserRoleRequest,
) (*pbauth.AddUserRoleResponse, error) {
	return nil, InDevelopmentError
}

// RevokeUserRole revokes a role from a user
func (s Server) RevokeUserRole(
	ctx context.Context,
	request *pbauth.RevokeUserRoleRequest,
) (*pbauth.RevokeUserRoleResponse, error) {
	return nil, InDevelopmentError
}

// GetUserRoles gets all the roles of a user
func (s Server) GetUserRoles(
	ctx context.Context,
	request *pbauth.GetUserRolesRequest,
) (*pbauth.GetUserRolesResponse, error) {
	return nil, InDevelopmentError
}
