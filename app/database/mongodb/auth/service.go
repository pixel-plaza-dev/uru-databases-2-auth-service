package auth

import (
	"context"
	"errors"
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb"
	commonmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb/model/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/user"
	"go.mongodb.org/mongo-driver/bson"
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

// FindRefreshToken finds a refresh token in the database
func (d *Database) FindRefreshToken(
	ctx context.Context,
	filter interface{},
	projection interface{},
	sort interface{},
) (
	*commonmongodbauth.JwtRefreshToken,
	error,
) {
	// Set the default projection
	if projection == nil {
		projection = bson.M{"_id": 1}
	}

	// Create the find options
	findOptions := commonmongodb.PrepareFindOneOptions(projection, sort)

	// Initialize the jwtRefreshToken variable
	jwtRefreshToken := &commonmongodbauth.JwtRefreshToken{}

	// Find the refresh token
	err := d.GetCollection(JwtRefreshTokenCollection).FindOne(
		ctx,
		filter,
		findOptions,
	).Decode(jwtRefreshToken)
	return jwtRefreshToken, err
}

// IsRefreshTokenValid checks if a refresh token is valid
func (d *Database) IsRefreshTokenValid(ctx context.Context, jwtId string) (
	valid bool,
	err error,
) {
	// Create the object ID
	jwtObjectId, err := primitive.ObjectIDFromHex(jwtId)
	if err != nil {
		return false, err
	}

	// Find the refresh token
	_, err = d.FindRefreshToken(
		ctx,
		bson.M{"_id": jwtObjectId, "revoked_at": bson.M{"$exists": false}},
		nil,
		nil,
	)
	return err != nil, err
}

// FindUserRefreshTokens gets all the user's refresh tokens
func (d *Database) FindUserRefreshTokens(
	ctx context.Context,
	userId string,
	projection interface{},
	sort interface{},
) (
	refreshTokens []*commonmongodbauth.JwtRefreshToken,
	err error,
) {
	// Convert the user ID to an object ID
	userObjectId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return nil, err
	}

	// Create the find options
	findOptions := commonmongodb.PrepareFindOptions(projection, sort, 0, 0)

	// Find the sessions
	cursor, err := d.GetCollection(JwtRefreshTokenCollection).Find(
		ctx,
		bson.M{"user_id": userObjectId, "revoked_at": bson.M{"$exists": false}},
		findOptions,
	)
	if err != nil {
		return nil, err
	}

	// Iterate through the cursor
	for cursor.Next(ctx) {
		// Decode the session
		var refreshToken commonmongodbauth.JwtRefreshToken
		if err = cursor.Decode(&refreshToken); err != nil {
			return nil, err
		}
		refreshTokens = append(refreshTokens, &refreshToken)
	}
	return refreshTokens, nil
}

// GetUserRefreshTokens gets all the user's refresh tokens
func (d *Database) GetUserRefreshTokens(
	ctx context.Context,
	userId string,
) (
	sessions []*commonmongodbauth.JwtRefreshToken,
	err error,
) {
	// Find the user's sessions
	sessions, err = d.FindUserRefreshTokens(
		ctx,
		userId,
		bson.M{"_id": 1, "issued_at": 1, "expires_at": 1},
		bson.M{"issued_at": -1},
	)
	return sessions, err
}

// FindAccessToken finds an access token in the database
func (d *Database) FindAccessToken(
	ctx context.Context,
	filter interface{},
	projection interface{},
	sort interface{},
) (
	*commonmongodbauth.JwtAccessToken,
	error,
) {
	// Set the default projection
	if projection == nil {
		projection = bson.M{"_id": 1}
	}

	// Create the find options
	findOptions := commonmongodb.PrepareFindOneOptions(projection, sort)

	// Initialize the jwtAccessToken variable
	jwtAccessToken := &commonmongodbauth.JwtAccessToken{}

	// Find the access token
	err := d.GetCollection(JwtAccessTokenCollection).FindOne(
		ctx,
		filter,
		findOptions,
	).Decode(jwtAccessToken)
	return jwtAccessToken, err
}

// IsAccessTokenValid checks if an access token is valid
func (d *Database) IsAccessTokenValid(ctx context.Context, jwtId string) (
	valid bool,
	err error,
) {
	// Create the object ID
	jwtObjectId, err := primitive.ObjectIDFromHex(jwtId)
	if err != nil {
		return false, err
	}

	// Find the access token
	_, err = d.FindAccessToken(
		ctx,
		bson.M{"_id": jwtObjectId, "revoked_at": bson.M{"$exists": false}},
		nil,
		nil,
	)
	return !errors.Is(err, mongo.ErrNoDocuments), err
}

// UpdateJwtRefreshToken updates a JWT refresh token in the database
func (d *Database) UpdateJwtRefreshToken(
	ctx context.Context,
	filter interface{},
	update interface{},
) (
	err error,
) {
	_, err = d.GetCollection(JwtRefreshTokenCollection).UpdateOne(
		ctx,
		filter,
		update,
	)
	return err
}

// UpdateJwtAccessToken updates a JWT access token in the database
func (d *Database) UpdateJwtAccessToken(
	ctx context.Context,
	filter interface{},
	update interface{},
) (
	err error,
) {
	_, err = d.GetCollection(JwtAccessTokenCollection).UpdateOne(
		ctx,
		filter,
		update,
	)
	return err
}

// RevokeUserRefreshToken revokes user's refresh token and its access token
func (d *Database) RevokeUserRefreshToken(
	jwtId string,
	userId string,
) (
	err error,
) {
	// Create the objects ID from the JWT and user IDs
	var objectsId = make(map[string]primitive.ObjectID)
	for _, id := range []string{jwtId, userId} {
		objectId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return err
		}

		objectsId[id] = objectId
	}

	// Run the transaction
	err = commonmongodb.CreateTransaction(
		d.client, func(sc mongo.SessionContext) error {
			// Update the refresh token
			if err = d.UpdateJwtRefreshToken(
				sc,
				bson.M{"_id": objectsId[jwtId], "user_id": objectsId[userId]},
				bson.M{"$set": bson.M{"revoked_at": time.Now()}},
			); err != nil {
				return err
			}

			// Update its access token
			err = d.UpdateJwtAccessToken(
				sc,
				bson.M{"jwt_refresh_token_id": objectsId[jwtId]},
				bson.M{"$set": bson.M{"revoked_at": time.Now()}},
			)
			return err
		},
	)
	return err
}
