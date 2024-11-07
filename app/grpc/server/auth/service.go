package auth

import (
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb/database/auth"
	protobuf "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled-protobuf/auth"
	"golang.org/x/net/context"
)

// Server is the gRPC auth server
type Server struct {
	authDatabase *auth.Database
	logger       auth.Logger
	// protobuf.UnimplementedAuthServer
}

// NewServer creates a new gRPC auth server
func NewServer(authDatabase *auth.Database, logger auth.Logger) *Server {
	return &Server{authDatabase: authDatabase, logger: logger}
}

func (s Server) LogIn(ctx context.Context, request *protobuf.LogInRequest) (*protobuf.LogInResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) RefreshToken(ctx context.Context, request *protobuf.RefreshTokenRequest) (*protobuf.RefreshTokenResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) LogOut(ctx context.Context, request *protobuf.LogOutRequest) (*protobuf.LogOutResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) CloseSessions(ctx context.Context, request *protobuf.CloseSessionsRequest) (*protobuf.CloseSessionsResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) AddPermission(ctx context.Context, request *protobuf.AddPermissionRequest) (*protobuf.AddPermissionResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) RevokePermission(ctx context.Context, request *protobuf.RevokePermissionRequest) (*protobuf.RevokePermissionResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) AddRolePermission(ctx context.Context, request *protobuf.AddRolePermissionRequest) (*protobuf.AddRolePermissionResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) RevokeRolePermission(ctx context.Context, request *protobuf.RevokeRolePermissionRequest) (*protobuf.RevokeRolePermissionResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) AddRole(ctx context.Context, request *protobuf.AddRoleRequest) (*protobuf.AddRoleResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) RevokeRole(ctx context.Context, request *protobuf.RevokeRoleRequest) (*protobuf.RevokeRoleResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s Server) mustEmbedUnimplementedAuthServer() {
	//TODO implement me
	panic("implement me")
}
