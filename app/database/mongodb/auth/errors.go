package auth

import (
	"errors"
)

var (
	NilDatabaseError   = errors.New("auth database cannot be nil")
	InDevelopmentError = errors.New("in development")
)
