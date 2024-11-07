package auth

import (
	commonmessage "github.com/pixel-plaza-dev/uru-databases-2-api-common/message"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	InternalError = status.Error(codes.Internal, commonmessage.Internal)
)
