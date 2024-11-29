package auth

import commonlogger "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/utils/logger"

type Logger struct {
	logger commonlogger.Logger
}

// NewLogger is the logger for the user database
func NewLogger(logger commonlogger.Logger) Logger {
	return Logger{logger: logger}
}

// LoggedIn logs that the user logged in
func (l Logger) LoggedIn(userId string, username string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"User logged in",
			commonlogger.StatusInfo,
			userId,
			username,
		),
	)
}

// FailedToCreateUserLogInAttempt logs that the user failed to create a user log in attempt
func (l Logger) FailedToCreateUserLogInAttempt(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to create user log in attempt",
			err,
		),
	)
}

// FailedToLogIn logs that the user failed to log in
func (l Logger) FailedToLogIn(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to log in",
			err,
		),
	)
}
