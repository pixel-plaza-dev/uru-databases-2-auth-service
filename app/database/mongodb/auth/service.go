package auth

import (
	"context"
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb"
	commonmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb/model/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/user"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
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

// NewUserLogInAttempt creates a new user log in attempt object
func (d *Database) NewUserLogInAttempt(
	userId *primitive.ObjectID,
	ipAddress string,
	success bool,
) *commonmongodbauth.UserLogInAttempt {
	return &commonmongodbauth.UserLogInAttempt{
		ID:           primitive.NewObjectID(),
		IPv4Address:  ipAddress,
		UserID:       *userId,
		AttemptedAt:  time.Now(),
		IsSuccessful: success,
	}
}

// InsertUserLogInAttempt inserts a user log in attempt into the database
func (d *Database) InsertUserLogInAttempt(
	ctx context.Context,
	userLogInAttempt *commonmongodbauth.UserLogInAttempt,
) (
	err error,
) {
	_, err = d.GetCollection(UserLogInAttemptCollection).InsertOne(
		ctx,
		userLogInAttempt,
	)
	return err
}

// CreateUserLogInAttempt creates a new user log in attempt and inserts it into the database
func (d *Database) CreateUserLogInAttempt(
	ctx context.Context,
	userId *primitive.ObjectID,
	ipAddress string,
	success bool,
) (
	err error,
) {
	// Create the UserLogInAttempt object
	userLogInAttempt := d.NewUserLogInAttempt(
		userId,
		ipAddress,
		success,
	)

	// Insert user log in attempt
	err = d.InsertUserLogInAttempt(ctx, userLogInAttempt)
	return err
}

// InsertJwtAccessToken inserts a JWT access token into the database
func (d *Database) InsertJwtAccessToken(
	ctx context.Context,
	jwtAccessToken *commonmongodbauth.JwtAccessToken,
) (
	err error,
) {
	_, err = d.GetCollection(JwtAccessTokenCollection).InsertOne(
		ctx,
		jwtAccessToken,
	)
	return err
}

// InsertJwtRefreshToken inserts a JWT refresh token into the database
func (d *Database) InsertJwtRefreshToken(
	jwtRefreshToken *commonmongodbauth.JwtRefreshToken,
	jwtAccessToken *commonmongodbauth.JwtAccessToken,
	userLogInAttempt *commonmongodbauth.UserLogInAttempt,
) (
	err error,
) {
	// Run the transaction
	err = commonmongodb.CreateTransaction(
		d.client, func(sc mongo.SessionContext) error {
			// Insert JWT refresh token
			if _, err = d.GetCollection(JwtRefreshTokenCollection).InsertOne(
				sc,
				jwtRefreshToken,
			); err != nil {
				return err
			}

			// Insert JWT access token
			if err = d.InsertJwtAccessToken(sc, jwtAccessToken); err != nil {
				return err
			}

			// Insert user log in attempt if it exists
			if userLogInAttempt != nil {
				err = d.InsertUserLogInAttempt(sc, userLogInAttempt)
				return err
			}
			return nil
		},
	)
	return err
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
