package auth

import (
	commonlogger "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/utils/logger"
	"strconv"
)

type Logger struct {
	logger commonlogger.Logger
}

// NewLogger is the logger for the user database
func NewLogger(logger commonlogger.Logger) (*Logger, error) {
	// Check if the logger is nil
	if logger == nil {
		return nil, commonlogger.NilLoggerError
	}

	return &Logger{logger: logger}, nil
}

// LoggedIn logs that the user logged in
func (l *Logger) LoggedIn(userId string, username string) {
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
func (l *Logger) FailedToCreateUserLogInAttempt(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to create user log in attempt",
			err,
		),
	)
}

// FailedToLogIn logs that the user failed to log in
func (l *Logger) FailedToLogIn(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to log in",
			err,
		),
	)
}

// FailedToAddTokenToRedis logs that the user failed to add a token to Redis
func (l *Logger) FailedToAddTokenToRedis(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to add token to Redis",
			err,
		),
	)
}

// CheckedIfAccessTokenIsValid logs that has been checked if the access token is valid
func (l *Logger) CheckedIfAccessTokenIsValid(jwtId string, isValid bool) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Checked if access token is valid",
			commonlogger.StatusInfo,
			jwtId,
			strconv.FormatBool(isValid),
		),
	)
}

// FailedToCheckIfAccessTokenIsValid logs that it failed to check if the access token is valid
func (l *Logger) FailedToCheckIfAccessTokenIsValid(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to check if access token is valid",
			err,
		),
	)
}

// TokenNotFound logs that the token was not found
func (l *Logger) TokenNotFound(jwtId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Token not found",
			commonlogger.StatusInfo,
			jwtId,
		),
	)
}

// UserTokenNotFound logs that the user's token was not found
func (l *Logger) UserTokenNotFound(userId string, jwtId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Token not found",
			commonlogger.StatusInfo,
			userId,
			jwtId,
		),
	)
}

// CheckedIfRefreshTokenIsValid logs that has been checked if the refresh token is valid
func (l *Logger) CheckedIfRefreshTokenIsValid(jwtId string, isValid bool) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Checked if refresh token is valid",
			commonlogger.StatusInfo,
			jwtId,
			strconv.FormatBool(isValid),
		),
	)
}

// FailedToCheckIfRefreshTokenIsValid logs that it failed to check if the refresh token is valid
func (l *Logger) FailedToCheckIfRefreshTokenIsValid(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to check if refresh token is valid",
			err,
		),
	)
}

// GetRefreshTokenInformation logs that the refresh token information has been retrieved
func (l *Logger) GetRefreshTokenInformation(userId string, jwtId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Get refresh token information",
			commonlogger.StatusInfo,
			userId,
			jwtId,
		),
	)
}

// FailedToGetRefreshTokenInformation logs that it failed to get the refresh token information
func (l *Logger) FailedToGetRefreshTokenInformation(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to get refresh token information",
			err,
		),
	)
}

// GetRefreshTokensInformation logs that the refresh tokens information has been retrieved
func (l *Logger) GetRefreshTokensInformation(userId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Get refresh tokens information",
			commonlogger.StatusInfo,
			userId,
		),
	)
}

// FailedToGetRefreshTokensInformation logs that it failed to get the refresh tokens information
func (l *Logger) FailedToGetRefreshTokensInformation(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to get refresh tokens information",
			err,
		),
	)
}

// RevokeUserRefreshToken logs that the user's refresh token has been revoked
func (l *Logger) RevokeUserRefreshToken(userId string, jwtId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Revoke user's refresh token",
			commonlogger.StatusInfo,
			userId,
			jwtId,
		),
	)
}

// FailedToRevokeUserRefreshToken logs that it failed to revoke the user's refresh token
func (l *Logger) FailedToRevokeUserRefreshToken(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to revoke user's refresh token",
			err,
		),
	)
}

// RevokeUserRefreshTokens logs that the user's refresh tokens have been revoked
func (l *Logger) RevokeUserRefreshTokens(userId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Revoke user's refresh tokens",
			commonlogger.StatusInfo,
			userId,
		),
	)
}

// FailedToRevokeUserRefreshTokens logs that it failed to revoke the user's refresh tokens
func (l *Logger) FailedToRevokeUserRefreshTokens(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to revoke user's refresh tokens",
			err,
		),
	)
}

// LogOut logs that the user has logged out
func (l *Logger) LogOut(userId string, jwtId string) {
	l.logger.LogMessage(
		commonlogger.NewLogMessage(
			"Log out",
			commonlogger.StatusInfo,
			userId,
			jwtId,
		),
	)
}

// FailedToLogOut logs that it failed to log out
func (l *Logger) FailedToLogOut(err error) {
	l.logger.LogError(
		commonlogger.NewLogError(
			"Failed to log out",
			err,
		),
	)
}
