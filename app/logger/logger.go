package logger

import (
	authserver "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth"
	commonenv "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/env"
	commonflag "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/flag"
	commonjwtvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/validator"
	commondatabase "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database"
	commonlistener "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/listener"
	commonlogger "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/utils/logger"
)

var (
	// Flag is the logger for the flag
	Flag, _ = commonflag.NewLogger(commonlogger.NewDefaultLogger("Flag"))

	// Listener is the logger for the listener
	Listener, _ = commonlistener.NewLogger(commonlogger.NewDefaultLogger("Net Listener"))

	// Environment is the logger for the environment
	Environment, _ = commonenv.NewLogger(commonlogger.NewDefaultLogger("Environment"))

	// MongoDb is the logger for the MongoDB client
	MongoDb, _ = commondatabase.NewLogger(commonlogger.NewDefaultLogger("MongoDB"))

	// AuthServer is the logger for the auth server
	AuthServer, _ = authserver.NewLogger(commonlogger.NewDefaultLogger("Auth Server"))

	// JwtValidator is the logger for the JWT validator
	JwtValidator, _ = commonjwtvalidator.NewLogger(commonlogger.NewDefaultLogger("JWT Validator"))
)
