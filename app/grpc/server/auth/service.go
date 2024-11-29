package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	appmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	authservervalidator "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth/validator"
	appjwt "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt"
	commonjwtissuer "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/issuer"
	commonmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb/model/auth"
	commonredisauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/redis/auth"
	commongrpcclientctx "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/client/context"
	commongrpcserverctx "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/context"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/user"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

// Server is the gRPC auth server
type Server struct {
	authDatabase        *appmongodbauth.Database
	userClient          pbuser.UserClient
	jwtIssuer           commonjwtissuer.Issuer
	jwtTokensDuration   map[string]time.Duration
	logger              Logger
	redisTokenValidator commonredisauth.TokenValidator
	validator           *authservervalidator.Validator
	pbauth.UnimplementedAuthServer
}

// NewServer creates a new gRPC auth server
func NewServer(
	authDatabase *appmongodbauth.Database,
	userClient pbuser.UserClient,
	jwtIssuer commonjwtissuer.Issuer,
	jwtTokensDuration map[string]time.Duration,
	logger Logger,
	redisTokenValidator commonredisauth.TokenValidator,
	validator *authservervalidator.Validator,
) *Server {
	return &Server{
		authDatabase:        authDatabase,
		userClient:          userClient,
		jwtIssuer:           jwtIssuer,
		jwtTokensDuration:   jwtTokensDuration,
		logger:              logger,
		redisTokenValidator: redisTokenValidator,
		validator:           validator,
	}
}

// LogIn logs in a user
func (s Server) LogIn(
	ctx context.Context,
	request *pbauth.LogInRequest,
) (response *pbauth.LogInResponse, err error) {
	// Validate the request
	if err = s.validator.ValidateLogInRequest(request); err != nil {
		s.logger.FailedToLogIn(err)
		return nil, err
	}

	// Get outgoing gRPC context
	grpcCtx, err := commongrpcclientctx.GetOutgoingCtx(ctx)
	if err != nil {
		return nil, InternalServerError
	}

	// Check if the password is correct and get the user ID
	user, err := s.userClient.IsPasswordCorrect(
		grpcCtx,
		&pbuser.IsPasswordCorrectRequest{
			Username: request.GetUsername(),
			Password: request.GetPassword(),
		},
	)
	if err != nil && status.Code(err) != codes.InvalidArgument {
		s.logger.FailedToLogIn(err)
		return nil, err
	}

	// Get the user ID object ID from the user ID string
	userObjectId, objectIdErr := primitive.ObjectIDFromHex(user.GetUserId())
	if objectIdErr != nil {
		s.logger.FailedToLogIn(objectIdErr)
		return nil, InternalServerError
	}

	// Get the parsed shared user ID from the shared user ID string
	userSharedId, uuidErr := uuid.Parse(user.GetUserSharedId())
	if uuidErr != nil {
		s.logger.FailedToLogIn(uuidErr)
		return nil, InternalServerError
	}

	// Get the client IP address
	ipAddress, ipErr := commongrpcserverctx.GetClientIP(ctx)
	if ipErr != nil {
		ipAddress = ""
	}

	// Create the user log in attempt
	newUserLogInAttempt := s.authDatabase.NewUserLogInAttempt(
		&userObjectId,
		ipAddress,
		err == nil,
	)

	// Check if the password is incorrect
	if err != nil {
		// Log in failed
		s.logger.FailedToLogIn(err)

		// Insert the user log in attempt
		if databaseErr := s.authDatabase.InsertUserLogInAttempt(
			context.Background(),
			newUserLogInAttempt,
		); databaseErr != nil {
			s.logger.FailedToCreateUserLogInAttempt(databaseErr)
			return nil, InternalServerError
		}
		return nil, err
	}

	// Get the issued time and the expiration time
	issuedAt := time.Now()
	refreshExpiresAt := commonjwtissuer.GetExpirationTime(
		issuedAt,
		s.jwtTokensDuration[appjwt.RefreshTokenDuration],
	)
	accessExpiresAt := commonjwtissuer.GetExpirationTime(
		issuedAt,
		s.jwtTokensDuration[appjwt.AccessTokenDuration],
	)

	// Create the MongoDB JWT refresh token object
	refreshId := primitive.NewObjectID()
	newRefreshToken := commonmongodbauth.JwtRefreshToken{
		ID:                 refreshId,
		UserID:             userObjectId,
		UserLogInAttemptID: newUserLogInAttempt.ID,
		IssuedAt:           issuedAt,
		ExpiresAt:          refreshExpiresAt,
	}

	// Create the MongoDB JWT access token object
	accessId := primitive.NewObjectID()
	newAccessToken := commonmongodbauth.JwtAccessToken{
		ID:                accessId,
		UserID:            userObjectId,
		JwtRefreshTokenID: refreshId,
		IssuedAt:          issuedAt,
		ExpiresAt:         accessExpiresAt,
	}

	// Create the JWT claims
	var newTokensClaims = make(map[string]*jwt.MapClaims)
	for _, token := range []string{appjwt.AccessToken, appjwt.RefreshToken} {
		newTokensClaims[token] = commonjwtissuer.GenerateClaims(
			refreshId.String(),
			user.GetUserId(),
			userSharedId,
			issuedAt,
			refreshExpiresAt,
			token == appjwt.RefreshToken,
		)
	}

	// Issue the JWT tokens
	var newIssuedTokens = make(map[string]string)
	for token, claims := range newTokensClaims {
		issuedToken, tokenErr := s.jwtIssuer.IssueToken(claims)
		if tokenErr != nil {
			s.logger.FailedToLogIn(tokenErr)
			return nil, InternalServerError
		}
		newIssuedTokens[token] = issuedToken
	}

	// Insert the tokens and the user log in attempt into the database
	if err = s.authDatabase.InsertJwtRefreshToken(
		&newRefreshToken,
		&newAccessToken,
		newUserLogInAttempt,
	); err != nil {
		s.logger.FailedToLogIn(err)
		return nil, InternalServerError
	}

	// User logged in successfully
	s.logger.LoggedIn(user.GetUserId(), request.GetUsername())

	return &pbauth.LogInResponse{
		Message:      LoggedIn,
		RefreshToken: newIssuedTokens[appjwt.RefreshToken],
		AccessToken:  newIssuedTokens[appjwt.AccessToken],
	}, nil
}

// IsAccessTokenValid checks if an access token is valid
func (s Server) IsAccessTokenValid(
	ctx context.Context,
	request *pbauth.IsAccessTokenValidRequest,
) (*pbauth.IsAccessTokenValidResponse, error) {
	// Check redis
	return nil, InDevelopmentError
}

// IsRefreshTokenValid checks if a refresh token is valid
func (s Server) IsRefreshTokenValid(
	ctx context.Context,
	request *pbauth.IsRefreshTokenValidRequest,
) (*pbauth.IsRefreshTokenValidResponse, error) {
	// Check redis
	return nil, InDevelopmentError
}

// RefreshToken refreshes a token
func (s Server) RefreshToken(
	ctx context.Context,
	request *pbauth.RefreshTokenRequest,
) (*pbauth.RefreshTokenResponse, error) {
	// Check redis
	return nil, InDevelopmentError
}

// LogOut logs out a user
func (s Server) LogOut(
	ctx context.Context,
	request *pbauth.LogOutRequest,
) (*pbauth.LogOutResponse, error) {
	// Check redis
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
	// Check redis
	return nil, InDevelopmentError
}

// CloseSessions closes user' sessions
func (s Server) CloseSessions(
	ctx context.Context,
	request *pbauth.CloseSessionsRequest,
) (*pbauth.CloseSessionsResponse, error) {
	// Check redis
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
