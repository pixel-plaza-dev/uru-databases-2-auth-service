package auth

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	InternalServerError = status.Error(codes.Internal, "internal server error")
	InDevelopmentError  = status.Error(codes.Internal, "in development")
)
