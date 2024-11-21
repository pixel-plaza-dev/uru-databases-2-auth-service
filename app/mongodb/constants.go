package mongodb

import (
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb"
)

const (
	// UriKey is the key of the MongoDB host
	UriKey = "AUTH_SERVICE_MONGODB_HOST"

	// DbNameKey is the key of the MongoDB database name
	DbNameKey = "AUTH_SERVICE_MONGODB_NAME"
)

var (
	// JwtAccessTokenCollection is the JWT access token collection in MongoDB
	JwtAccessTokenCollection = commonmongodb.NewCollection(
		"JwtAccessToken",
		nil,
		nil,
	)

	// JwtAccessTokenLogCollection is the JWT access token log collection in MongoDB
	JwtAccessTokenLogCollection = commonmongodb.NewCollection(
		"JwtAccessTokenLog",
		nil,
		nil,
	)

	// JwtRefreshTokenCollection is the JWT refresh token collection in MongoDB
	JwtRefreshTokenCollection = commonmongodb.NewCollection(
		"JwtRefreshToken",
		nil,
		nil,
	)

	// JwtRefreshTokenLogCollection is the JWT refresh token log collection in MongoDB
	JwtRefreshTokenLogCollection = commonmongodb.NewCollection(
		"JwtRefreshTokenLog",
		nil,
		nil,
	)

	// PermissionCollection is the permission collection in MongoDB
	PermissionCollection = commonmongodb.NewCollection("Permission", nil, nil)

	// RoleCollection is the role collection in MongoDB
	RoleCollection = commonmongodb.NewCollection("Role", nil, nil)

	// RolePermissionCollection is the role permission collection in MongoDB
	RolePermissionCollection = commonmongodb.NewCollection(
		"RolePermission",
		nil,
		nil,
	)

	// UserLogInAttemptCollection is the user log in attempt collection in MongoDB
	UserLogInAttemptCollection = commonmongodb.NewCollection(
		"UserLogInAttempt",
		nil,
		nil,
	)

	// UserRoleCollection is the user role collection in MongoDB
	UserRoleCollection = commonmongodb.NewCollection("UserRole", nil, nil)
)
