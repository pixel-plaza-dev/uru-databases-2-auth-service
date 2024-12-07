package auth

import (
	"errors"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	appmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	authservervalidator "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth/validator"
	appjwt "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt"
	commonjwtissuer "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/issuer"
	commonjwtvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/validator"
	commonmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb/model/auth"
	commonredisauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/redis/auth"
	commongrpcclientctx "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/client/context"
	commongrpcserverctx "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/context"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/user"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pbempty "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	jwtValidatorLogger  commonjwtvalidator.Logger
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
	jwtValidatorLogger commonjwtvalidator.Logger,
) *Server {
	return &Server{
		authDatabase:        authDatabase,
		userClient:          userClient,
		jwtIssuer:           jwtIssuer,
		jwtTokensDuration:   jwtTokensDuration,
		logger:              logger,
		redisTokenValidator: redisTokenValidator,
		validator:           validator,
		jwtValidatorLogger:  jwtValidatorLogger,
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
	var expiresAt = make(map[string]time.Time)
	for _, token := range []string{appjwt.RefreshToken, appjwt.AccessToken} {
		expiresAt[token] = commonjwtissuer.GetExpirationTime(
			issuedAt,
			s.jwtTokensDuration[token],
		)
	}

	// Create the JWT ID
	var jwtIds = make(map[string]primitive.ObjectID)
	for _, token := range []string{appjwt.RefreshToken, appjwt.AccessToken} {
		jwtIds[token] = primitive.NewObjectID()
	}

	// Create the MongoDB JWT refresh token object
	refreshId := primitive.NewObjectID()
	newRefreshToken := commonmongodbauth.JwtRefreshToken{
		ID:                 jwtIds[appjwt.RefreshToken],
		UserID:             userObjectId,
		UserLogInAttemptID: newUserLogInAttempt.ID,
		IPv4Address:        ipAddress,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt[appjwt.RefreshToken],
	}

	// Create the MongoDB JWT access token object
	newAccessToken := commonmongodbauth.JwtAccessToken{
		ID:                jwtIds[appjwt.AccessToken],
		UserID:            userObjectId,
		JwtRefreshTokenID: refreshId,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt[appjwt.AccessToken],
	}

	// Create the JWT claims
	var newTokensClaims = make(map[string]*jwt.MapClaims)
	for _, token := range []string{appjwt.AccessToken, appjwt.RefreshToken} {
		newTokensClaims[token] = commonjwtissuer.GenerateClaims(
			jwtIds[token].Hex(),
			user.GetUserId(),
			userSharedId,
			issuedAt,
			expiresAt[token],
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

	// If Redis is enabled, insert the refresh and access token into it
	if s.redisTokenValidator != nil {
		for _, token := range []string{
			appjwt.AccessToken,
			appjwt.RefreshToken,
		} {
			if err = s.redisTokenValidator.AddToken(
				jwtIds[token].String(),
				s.jwtTokensDuration[token],
			); err != nil {
				s.logger.FailedToAddTokenToRedis(err)
			}
		}
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
) (response *pbauth.IsAccessTokenValidResponse, err error) {
	// Validate the request
	if err = s.validator.ValidateIsAccessTokenValidRequest(request); err != nil {
		s.logger.FailedToCheckIfAccessTokenIsValid(err)
		return nil, InternalServerError
	}

	// If Redis is enabled, check if the token is in Redis
	var isValid bool
	if s.redisTokenValidator != nil {
		isValid, err = s.redisTokenValidator.IsTokenValid(request.GetJwtId())
	} else {
		isValid, err = s.authDatabase.IsAccessTokenValid(
			context.Background(),
			request.GetJwtId(),
		)
	}

	// Check if there was an error
	if err != nil && !errors.Is(
		mongo.ErrNoDocuments,
		err,
	) && !errors.Is(redis.Nil, err) {
		s.logger.FailedToCheckIfAccessTokenIsValid(err)
		return nil, InternalServerError
	}

	// Check if the token was not found
	if err != nil {
		s.logger.TokenNotFound(request.GetJwtId())
		if s.redisTokenValidator != nil {
			return nil, status.Error(codes.NotFound, TokenNotFoundOrHasExpired)
		}
		return nil, status.Error(codes.NotFound, TokenNotFound)
	}

	// Checked if the token is valid
	s.logger.CheckedIfAccessTokenIsValid(request.GetJwtId(), isValid)

	return &pbauth.IsAccessTokenValidResponse{
		Message: CheckedIfAccessTokenIsValid,
		IsValid: isValid,
	}, nil
}

// IsRefreshTokenValid checks if a refresh token is valid
func (s Server) IsRefreshTokenValid(
	ctx context.Context,
	request *pbauth.IsRefreshTokenValidRequest,
) (response *pbauth.IsRefreshTokenValidResponse, err error) {
	// Validate the request
	if err = s.validator.ValidateIsRefreshTokenValidRequest(request); err != nil {
		s.logger.FailedToCheckIfRefreshTokenIsValid(err)
		return nil, InternalServerError
	}

	// If Redis is enabled, check if the token is in Redis
	var isValid bool
	if s.redisTokenValidator != nil {
		isValid, err = s.redisTokenValidator.IsTokenValid(request.GetJwtId())
	} else {
		isValid, err = s.authDatabase.IsRefreshTokenValid(
			context.Background(),
			request.GetJwtId(),
		)
	}

	// Check if there was an error
	if err != nil && !errors.Is(
		mongo.ErrNoDocuments,
		err,
	) && !errors.Is(redis.Nil, err) {
		s.logger.FailedToCheckIfRefreshTokenIsValid(err)
		return nil, InternalServerError
	}

	// Check if the token was not found
	if err != nil {
		s.logger.TokenNotFound(request.GetJwtId())
		if s.redisTokenValidator != nil {
			return nil, status.Error(codes.NotFound, TokenNotFoundOrHasExpired)
		}
		return nil, status.Error(codes.NotFound, TokenNotFound)
	}

	// Checked if the token is valid
	s.logger.CheckedIfRefreshTokenIsValid(request.GetJwtId(), isValid)

	return &pbauth.IsRefreshTokenValidResponse{
		Message: CheckedIfRefreshTokenIsValid,
		IsValid: isValid,
	}, nil
}

// GetRefreshTokensInformation gets all user's refresh tokens information
func (s Server) GetRefreshTokensInformation(
	ctx context.Context,
	request *pbempty.Empty,
) (*pbauth.GetRefreshTokensInformationResponse, error) {
	// Get the user ID from the access token
	userId, err := commongrpcserverctx.GetCtxTokenClaimsUserId(ctx)
	if err != nil {
		s.jwtValidatorLogger.MissingTokenClaimsUserId()
		return nil, InternalServerError
	}

	// Get the user's refresh tokens
	refreshTokens, err := s.authDatabase.GetUserRefreshTokens(
		context.Background(),
		userId,
	)
	if err != nil {
		s.logger.FailedToGetRefreshTokensInformation(err)
		return nil, InternalServerError
	}

	// Parse user's refresh tokens information
	var parsedRefreshTokens = make(
		[]*pbauth.RefreshTokenInformation,
		len(refreshTokens),
	)
	for i, userSession := range refreshTokens {
		parsedRefreshTokens[i] = &pbauth.RefreshTokenInformation{
			Id:          userSession.ID.Hex(),
			Ipv4Address: userSession.IPv4Address,
			IssuedAt:    timestamppb.New(userSession.IssuedAt),
			ExpiresAt:   timestamppb.New(userSession.ExpiresAt),
		}
	}

	// Fetched user's refresh tokens information successfully
	s.logger.GetRefreshTokensInformation(userId)

	return &pbauth.GetRefreshTokensInformationResponse{
		Message:                  FetchedUserRefreshTokens,
		RefreshTokensInformation: parsedRefreshTokens,
	}, nil
}

// RevokeRefreshToken revokes a user's refresh token
func (s Server) RevokeRefreshToken(
	ctx context.Context,
	request *pbauth.RevokeRefreshTokenRequest,
) (response *pbauth.RevokeRefreshTokenResponse, err error) {
	// Validate the request
	if err = s.validator.ValidateRevokeRefreshTokenRequest(request); err != nil {
		s.logger.FailedToRevokeUserRefreshToken(err)
		return nil, InternalServerError
	}

	// Get the user ID from the access token
	userId, err := commongrpcserverctx.GetCtxTokenClaimsUserId(ctx)
	if err != nil {
		s.jwtValidatorLogger.MissingTokenClaimsUserId()
		return nil, InternalServerError
	}

	// Revoke user's refresh token
	err = s.authDatabase.RevokeUserRefreshToken(
		request.GetJwtId(),
		userId,
	)
	if err != nil && !errors.Is(mongo.ErrNoDocuments, err) {
		s.logger.FailedToRevokeUserRefreshToken(err)
		return nil, InternalServerError
	}

	// Check if the user's refresh token was not found
	if err != nil {
		s.logger.UserTokenNotFound(userId, request.GetJwtId())
		return nil, status.Error(codes.NotFound, UserTokenNotFound)
	}

	// Revoke user's refresh tokens successfully
	s.logger.RevokeUserRefreshTokens(userId)

	return &pbauth.RevokeRefreshTokenResponse{
		Message: FetchedUserRefreshToken,
	}, nil
}

// GetRefreshTokenInformation gets the refresh token information
func (s Server) GetRefreshTokenInformation(
	ctx context.Context,
	request *pbauth.GetRefreshTokenInformationRequest,
) (*pbauth.GetRefreshTokenInformationResponse, error) {
	return nil, InDevelopmentError
}

// RevokeRefreshTokens revokes all the user's refresh tokens
func (s Server) RevokeRefreshTokens(
	ctx context.Context,
	request *pbempty.Empty,
) (*pbauth.RevokeRefreshTokensResponse, error) {
	// Check redis
	return nil, InDevelopmentError
}

// RefreshToken refreshes a token
func (s Server) RefreshToken(
	ctx context.Context,
	request *pbempty.Empty,
) (*pbauth.RefreshTokenResponse, error) {
	// Check redis
	return nil, InDevelopmentError
}

// LogOut logs out a user
func (s Server) LogOut(
	ctx context.Context,
	request *pbempty.Empty,
) (*pbauth.LogOutResponse, error) {
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
	request *pbempty.Empty,
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
	request *pbempty.Empty,
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
