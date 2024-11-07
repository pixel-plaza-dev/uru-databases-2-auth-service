package auth

import (
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/mongodb"
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/mongodb"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/context"
)

type Database struct {
	database    *mongo.Database
	collections *map[string]*commonmongodb.Collection
	client      *mongo.Client
}

// NewDatabase creates a new MongoDB auth database handler
func NewDatabase(client *mongo.Client, databaseName string) (database *Database, err error) {
	// Get the auth service database
	authServiceDb := client.Database(databaseName)

	// Create map of collections
	collections := make(map[string]*commonmongodb.Collection)

	for _, collection := range []*commonmongodb.Collection{
		mongodb.JwtAccessTokenLogCollection,
		mongodb.JwtRefreshTokenCollection,
		mongodb.JwtRefreshTokenLogCollection,
		mongodb.PermissionCollection,
		mongodb.RoleCollection,
		mongodb.RolePermissionCollection,
		mongodb.UserLogInAttemptCollection,
		mongodb.UserRoleCollection} {
		// Create the collection
		collections[collection.Name] = collection
		if _, err = collection.CreateCollection(authServiceDb); err != nil {
			return nil, err
		}
	}

	// Create the user database instance
	instance := &Database{client: client, database: authServiceDb, collections: &collections}

	return instance, nil
}

// Database returns the MongoDB users database
func (d *Database) Database() *mongo.Database {
	return d.database
}

// GetQueryContext returns a new query context
func (d *Database) GetQueryContext() (ctx context.Context, cancelFunc context.CancelFunc) {
	return context.WithTimeout(context.Background(), mongodb.QueryCtxTimeout)
}

// GetTransactionContext returns a new transaction context
func (d *Database) GetTransactionContext() (ctx context.Context, cancelFunc context.CancelFunc) {
	return context.WithTimeout(context.Background(), mongodb.TransactionCtxTimeout)
}

// GetCollection returns a collection
func (d *Database) GetCollection(collection *commonmongodb.Collection) *mongo.Collection {
	return d.database.Collection(collection.Name)
}

// InsertOne inserts a document into a collection
func (d *Database) InsertOne(collection *commonmongodb.Collection, document interface{}) (result *mongo.InsertOneResult, err error) {
	// Create the context
	ctx, cancelFunc := d.GetQueryContext()
	defer cancelFunc()

	// Insert the document
	result, err = d.GetCollection(collection).InsertOne(ctx, document)
	if err != nil {
		return nil, err
	}

	return result, nil
}
