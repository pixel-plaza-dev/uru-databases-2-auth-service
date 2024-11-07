package logger

import (
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb/database/auth"
	commonenv "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/env"
	commonflag "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/flag"
	commonlistener "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/listener"
	commonlogger "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/logger"
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/mongodb"
)

const (
	// FlagLoggerName is the name of the flag logger
	FlagLoggerName = "Flag"

	// ListenerLoggerName is the name of the listener logger
	ListenerLoggerName = "Net Listener"

	// EnvironmentLoggerName is the name of the environment logger
	EnvironmentLoggerName = "Environment"

	// MongoDbLoggerName is the name of the MongoDB logger
	MongoDbLoggerName = "MongoDB"

	// AuthDatabaseLoggerName is the name of the auth database logger
	AuthDatabaseLoggerName = "Auth Database"
)

var (
	// FlagLogger is the logger for the flag
	FlagLogger = commonflag.NewLogger(commonlogger.NewDefaultLogger(FlagLoggerName))

	// ListenerLogger is the logger for the listener
	ListenerLogger = commonlistener.NewLogger(commonlogger.NewDefaultLogger(ListenerLoggerName))

	// EnvironmentLogger is the logger for the environment
	EnvironmentLogger = commonenv.NewLogger(commonlogger.NewDefaultLogger(EnvironmentLoggerName))

	// MongoDbLogger is the logger for the MongoDB client
	MongoDbLogger = commonmongodb.NewLogger(commonlogger.NewDefaultLogger(MongoDbLoggerName))

	//

	// AuthDatabaseLogger is the logger for the auth database
	AuthDatabaseLogger = auth.NewLogger(commonlogger.NewDefaultLogger(AuthDatabaseLoggerName))
)
