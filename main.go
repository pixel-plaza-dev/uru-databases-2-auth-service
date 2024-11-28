package main

import (
	"context"
	"flag"
	"github.com/joho/godotenv"
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb"
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	appgrpc "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc"
	authserver "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth"
	authservervalidator "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth/validator"
	appjwt "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt"
	jwtvalidatorgrpc "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt/validator/grpc"
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/listener"
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/logger"
	commongcloud "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/cloud/gcloud"
	commonenv "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/env"
	commonflag "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/config/flag"
	commonjwtissuer "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/issuer"
	commonjwtvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/crypto/jwt/validator"
	commonmongodb "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/database/mongodb"
	clientauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/client/interceptor/auth"
	serverauth "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/interceptor/auth"
	commongrpcvalidator "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/grpc/server/validator"
	commonlistener "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/listener"
	commontls "github.com/pixel-plaza-dev/uru-databases-2-go-service-common/http/tls"
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/compiled/user"
	detailsauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/protobuf/details/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
	"net"
)

// Load environment variables
func init() {
	// Declare flags and parse them
	commonflag.SetModeFlag()
	flag.Parse()
	logger.FlagLogger.ModeFlagSet(commonflag.Mode)

	// Check if the environment is production
	if commonflag.Mode.IsProd() {
		return
	}

	if err := godotenv.Load(); err != nil {
		panic(commonenv.FailedToLoadEnvironmentVariablesError)
	}
}

func main() {
	// Get the listener port
	servicePort, err := commonlistener.LoadServicePort(
		"0.0.0.0",
		listener.PortKey,
	)
	if err != nil {
		panic(err)
	}
	logger.EnvironmentLogger.EnvironmentVariableLoaded(listener.PortKey)

	// Get the MongoDB URI
	mongoDbUri, err := commonenv.LoadVariable(auth.UriKey)
	if err != nil {
		panic(err)
	}
	logger.EnvironmentLogger.EnvironmentVariableLoaded(auth.UriKey)

	// Get the required MongoDB database name
	mongoDbName, err := commonenv.LoadVariable(auth.DbNameKey)
	if err != nil {

		panic(err)
	}
	logger.EnvironmentLogger.EnvironmentVariableLoaded(auth.DbNameKey)

	// Get the gRPC services URI
	var uris = make(map[string]string)
	for _, key := range []string{appgrpc.UserServiceUriKey} {
		uri, err := commonenv.LoadVariable(key)
		if err != nil {
			panic(err)
		}
		logger.EnvironmentLogger.EnvironmentVariableLoaded(key)
		uris[key] = uri
	}

	// Get the JWT keys
	var jwtKeys = make(map[string]string)
	for _, key := range []string{appjwt.PublicKey, appjwt.PrivateKey} {
		jwtKey, err := commonenv.LoadVariable(key)
		if err != nil {
			panic(err)
		}
		logger.EnvironmentLogger.EnvironmentVariableLoaded(key)
		jwtKeys[key] = jwtKey
	}

	// Load Google Cloud service account credentials
	googleCredentials, err := commongcloud.LoadGoogleCredentials(context.Background())
	if err != nil {
		panic(err)
	}

	// Get the service account token source for each gRPC server URI
	var tokenSources = make(map[string]*oauth.TokenSource)
	for key, uri := range uris {
		tokenSource, err := commongcloud.LoadServiceAccountCredentials(
			context.Background(), "https://"+uri, googleCredentials,
		)
		if err != nil {
			panic(err)
		}
		tokenSources[key] = tokenSource
	}

	// Get the MongoDB configuration
	mongoDbConfig := &commonmongodb.Config{
		Uri:     mongoDbUri,
		Timeout: mongodb.ConnectionCtxTimeout,
	}

	// Get the connection handler
	mongodbConnection := commonmongodb.NewDefaultConnectionHandler(mongoDbConfig)

	// Connect to MongoDB and get the client
	mongodbClient, err := mongodbConnection.Connect()
	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}
	defer func() {
		// Disconnect from MongoDB
		mongodbConnection.Disconnect()
		logger.MongoDbLogger.DisconnectedFromDatabase()
	}()
	logger.MongoDbLogger.ConnectedToDatabase()

	// Load transport credentials
	var transportCredentials credentials.TransportCredentials

	if commonflag.Mode.IsDev() {
		// Load server TLS credentials
		transportCredentials, err = credentials.NewServerTLSFromFile(
			appgrpc.ServerCertPath, appgrpc.ServerKeyPath,
		)
		if err != nil {
			panic(err)
		}
	} else {
		// Load system certificates pool
		transportCredentials, err = commontls.LoadSystemCredentials()
		if err != nil {
			panic(err)
		}
	}

	// Create client authentication interceptors
	var clientAuthInterceptors = make(map[string]*clientauth.Interceptor)
	for key, tokenSource := range tokenSources {
		clientAuthInterceptor, err := clientauth.NewInterceptor(tokenSource)
		if err != nil {
			panic(err)
		}
		clientAuthInterceptors[key] = clientAuthInterceptor
	}

	// Create gRPC connections
	var conns = make(map[string]*grpc.ClientConn)
	for key, uri := range uris {
		conn, err := grpc.NewClient(
			uri, grpc.WithTransportCredentials(transportCredentials),
			grpc.WithChainUnaryInterceptor(clientAuthInterceptors[key].Authenticate()),
		)
		if err != nil {
			panic(err)
		}
		conns[key] = conn
	}
	defer func(conns map[string]*grpc.ClientConn) {
		for _, conn := range conns {
			err = conn.Close()
			if err != nil {
				panic(err)
			}
		}
	}(conns)

	// Create gRPC server clients
	userClient := pbuser.NewUserClient(conns[appgrpc.UserServiceUriKey])

	// Create auth database handler
	authDatabase, err := auth.NewDatabase(
		mongodbClient,
		mongoDbName,
		userClient,
	)

	// Create token validator
	tokenValidator := jwtvalidatorgrpc.NewDefaultTokenValidator(
		authDatabase,
		nil,
	)

	// Create JWT validator
	jwtValidator, err := commonjwtvalidator.NewDefaultValidator(
		[]byte(jwtKeys[appjwt.PublicKey]),
		tokenValidator,
	)
	if err != nil {
		panic(err)
	}

	// Create the JWT issuer
	jwtIssuer, err := commonjwtissuer.NewDefaultIssuer([]byte(jwtKeys[appjwt.PrivateKey]))
	if err != nil {
		panic(err)
	}

	// Create server authentication interceptor
	serverAuthInterceptor, err := serverauth.NewInterceptor(
		jwtValidator,
		&detailsauth.GRPCInterceptions,
	)
	if err != nil {
		panic(err)
	}

	// Create the gRPC server
	s := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
		grpc.ChainUnaryInterceptor(
			serverAuthInterceptor.Authenticate(),
		),
	)

	// Create the gRPC server validator
	serverValidator := commongrpcvalidator.NewDefaultValidator()

	// Create the gRPC auth server validator
	authServerValidator := authservervalidator.NewValidator(
		authDatabase,
		serverValidator,
	)

	// Create the gRPC Auth Server
	authServer := authserver.NewServer(
		authDatabase,
		userClient,
		jwtIssuer,
		logger.AuthServerLogger,
		nil,
		authServerValidator,
	)

	// Register the auth server with the gRPC server
	pbauth.RegisterAuthServer(s, authServer)

	// Listen on the given port
	portListener, err := net.Listen("tcp", servicePort.FormattedPort)
	if err != nil {
		panic(commonlistener.FailedToListenError)
	}
	defer func() {
		if err := portListener.Close(); err != nil {
			panic(commonlistener.FailedToCloseError)
		}
	}()

	// Serve the gRPC server
	logger.ListenerLogger.ServerStarted(servicePort.Port)
	if err = s.Serve(portListener); err != nil {
		panic(commonlistener.FailedToServeError)
	}
	defer s.Stop()
}
