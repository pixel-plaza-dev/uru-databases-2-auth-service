package mongodb

import "time"

const (
	// ConnectionCtxTimeout is the timeout for the MongoDB connection
	ConnectionCtxTimeout = 60 * time.Second

	// QueryCtxTimeout is the MongoDB query context
	QueryCtxTimeout = 15 * time.Second

	// TransactionCtxTimeout is the MongoDB transaction context
	TransactionCtxTimeout = 60 * time.Second
)
