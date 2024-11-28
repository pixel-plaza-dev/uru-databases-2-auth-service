package auth

import (
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/user"
	"go.mongodb.org/mongo-driver/mongo"
)

type Database struct {
	database    *mongo.Database
	collections *map[string]*commonmongodb.Collection
	client      *mongo.Client
	userClient  pbuser.UserClient
}

// NewDatabase creates a new MongoDB auth database handler
func NewDatabase(
	client *mongo.Client,
	databaseName string,
	userClient pbuser.UserClient,
) (database *Database, err error) {
	// Get the auth service database
	authServiceDb := client.Database(databaseName)

	// Create map of collections
	collections := make(map[string]*commonmongodb.Collection)

	for _, collection := range []*commonmongodb.Collection{
		JwtAccessTokenLogCollection,
		JwtRefreshTokenCollection,
		JwtRefreshTokenLogCollection,
		PermissionCollection,
		RoleCollection,
		RolePermissionCollection,
		UserLogInAttemptCollection,
		UserRoleCollection,
	} {
		// Create the collection
		collections[collection.Name] = collection
		if _, err = collection.CreateCollection(authServiceDb); err != nil {
			return nil, err
		}
	}

	return &Database{
		client:      client,
		database:    authServiceDb,
		collections: &collections,
		userClient:  userClient,
	}, nil
}

// Database returns the MongoDB users database
func (d *Database) Database() *mongo.Database {
	return d.database
}

// GetCollection returns a collection
func (d *Database) GetCollection(collection *commonmongodb.Collection) *mongo.Collection {
	return d.database.Collection(collection.Name)
}

// IsRefreshTokenValid checks if a refresh token is valid
func (d *Database) IsRefreshTokenValid(refreshToken string) (
	valid bool,
	err error,
) {
	return false, InDevelopmentError
}

// IsAccessTokenValid checks if an access token is valid
func (d *Database) IsAccessTokenValid(accessToken string) (
	valid bool,
	err error,
) {
	return false, InDevelopmentError
}
