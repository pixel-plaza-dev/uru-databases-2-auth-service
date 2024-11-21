package logger

import (
	authserver "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth"
	authdatabase "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb/database/auth"
	commonenv "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/env"
	commonflag "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/flag"
	commondatabase "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database"
	commonlistener "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/listener"
	commonlogger "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/utils/logger"
)

var (
	// FlagLogger is the logger for the flag
	FlagLogger = commonflag.NewLogger(commonlogger.NewDefaultLogger("Flag"))

	// ListenerLogger is the logger for the listener
	ListenerLogger = commonlistener.NewLogger(commonlogger.NewDefaultLogger("Net Listener"))

	// EnvironmentLogger is the logger for the environment
	EnvironmentLogger = commonenv.NewLogger(commonlogger.NewDefaultLogger("Environment"))

	// MongoDbLogger is the logger for the MongoDB client
	MongoDbLogger = commondatabase.NewLogger(commonlogger.NewDefaultLogger("MongoDB"))

	// AuthServerLogger is the logger for the auth server
	AuthServerLogger = authserver.NewLogger(commonlogger.NewDefaultLogger("Auth Server"))

	// AuthDatabaseLogger is the logger for the auth database
	AuthDatabaseLogger = authdatabase.NewLogger(commonlogger.NewDefaultLogger("Auth Database"))
)
