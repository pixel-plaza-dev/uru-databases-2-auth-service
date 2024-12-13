package main

import (
	"context"
	"flag"
	"github.com/joho/godotenv"
	"github.com/pixel-plaza-dev/uru-databases-2-auth-service/app"
	appmongodb "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb"
	appmongodbauth "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/database/mongodb/auth"
	appgrpc "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc"
	authserver "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth"
	authservervalidator "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/grpc/server/auth/validator"
	appjwt "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt"
	jwtvalidatorgrpc "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/jwt/validator/grpc"
	applistener "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/listener"
	applogger "github.com/pixel-plaza-dev/uru-databases-2-auth-service/app/logger"
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
	pbauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/auth"
	pbuser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/compiled/pixel_plaza/user"
	pbconfigauth "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/config/grpc/auth"
	pbconfiguser "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/config/grpc/user"
	pbtypesgrpc "github.com/pixel-plaza-dev/uru-databases-2-protobuf-common/types/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
	"net"
	"time"
)

// Load environment variables
func init() {
	// Declare flags and parse them
	commonflag.SetModeFlag()
	flag.Parse()
	applogger.Flag.ModeFlagSet(commonflag.Mode)

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
		applistener.PortKey,
	)
	if err != nil {
		panic(err)
	}
	applogger.Environment.EnvironmentVariableLoaded(applistener.PortKey)

	// Get the MongoDB URI
	mongoDbUri, err := commonenv.LoadVariable(appmongodbauth.UriKey)
	if err != nil {
		panic(err)
	}
	applogger.Environment.EnvironmentVariableLoaded(appmongodbauth.UriKey)

	// Get the required MongoDB database name
	mongoDbName, err := commonenv.LoadVariable(appmongodbauth.DbNameKey)
	if err != nil {

		panic(err)
	}
	applogger.Environment.EnvironmentVariableLoaded(appmongodbauth.DbNameKey)

	// Get the gRPC services URI
	var uriKeys = []string{appgrpc.UserServiceUriKey}
	var uris = make(map[string]string)
	for _, uriKey := range uriKeys {
		uri, err := commonenv.LoadVariable(uriKey)
		if err != nil {
			panic(err)
		}
		applogger.Environment.EnvironmentVariableLoaded(uriKey)
		uris[uriKey] = uri
	}

	// Get the JWT keys
	var jwtKeys = make(map[string]string)
	for _, key := range []string{appjwt.PublicKey, appjwt.PrivateKey} {
		jwtKey, err := commonenv.LoadVariable(key)
		if err != nil {
			panic(err)
		}
		applogger.Environment.EnvironmentVariableLoaded(key)
		jwtKeys[key] = jwtKey
	}

	// Get the JWT tokens duration
	var jwtTokensDuration = make(map[string]time.Duration)
	for key, value := range map[string]string{
		appjwt.AccessToken:  appjwt.AccessTokenDuration,
		appjwt.RefreshToken: appjwt.RefreshTokenDuration,
	} {
		jwtTokenDuration, err := commonenv.LoadVariable(value)
		if err != nil {
			panic(err)
		}
		applogger.Environment.EnvironmentVariableLoaded(value)

		// Parse the duration
		parsedJwtTokenDuration, err := time.ParseDuration(jwtTokenDuration)
		if err != nil {
			panic(err)
		}
		jwtTokensDuration[key] = parsedJwtTokenDuration
	}

	// Load Google Cloud service account credentials
	googleCredentials, err := commongcloud.LoadGoogleCredentials(context.Background())
	if err != nil {
		panic(err)
	}

	// Get the service account token source for each gRPC server URI
	var tokenSources = make(map[string]*oauth.TokenSource)
	for _, uriKey := range uriKeys {
		tokenSource, err := commongcloud.LoadServiceAccountCredentials(
			context.Background(), "https://"+uris[uriKey], googleCredentials,
		)
		if err != nil {
			panic(err)
		}
		tokenSources[uriKey] = tokenSource
	}

	// Get the MongoDB configuration
	mongoDbConfig := &commonmongodb.Config{
		Uri:     mongoDbUri,
		Timeout: appmongodb.ConnectionCtxTimeout,
	}

	// Get the connection handler
	mongodbConnection, err := commonmongodb.NewDefaultConnectionHandler(mongoDbConfig)
	if err != nil {
		panic(err)
	}

	// Connect to MongoDB and get the client
	mongodbClient, err := mongodbConnection.Connect()
	if err != nil {
		panic(err)
	}
	defer func() {
		// Disconnect from MongoDB
		mongodbConnection.Disconnect()
		applogger.MongoDb.DisconnectedFromDatabase()
	}()
	applogger.MongoDb.ConnectedToDatabase()

	// Load transport credentials
	var transportCredentials credentials.TransportCredentials

	if commonflag.Mode.IsDev() {
		// Load server TLS credentials
		transportCredentials, err = credentials.NewServerTLSFromFile(
			app.ServerCertPath, app.ServerKeyPath,
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

	// Create gRPC interceptions map
	var grpcInterceptions = map[string]*map[pbtypesgrpc.Method]pbtypesgrpc.Interception{
		appgrpc.UserServiceUriKey: &pbconfiguser.Interceptions,
	}

	// Create client authentication interceptors
	var clientAuthInterceptors = make(map[string]*clientauth.Interceptor)
	for _, uriKey := range uriKeys {
		clientAuthInterceptor, err := clientauth.NewInterceptor(tokenSources[uriKey], grpcInterceptions[uriKey])
		if err != nil {
			panic(err)
		}
		clientAuthInterceptors[uriKey] = clientAuthInterceptor
	}

	// Create gRPC connections
	var conns = make(map[string]*grpc.ClientConn)
	for _, uriKey := range uriKeys {
		conn, err := grpc.NewClient(
			uris[uriKey], grpc.WithTransportCredentials(transportCredentials),
			grpc.WithChainUnaryInterceptor(clientAuthInterceptors[uriKey].Authenticate()),
		)
		if err != nil {
			panic(err)
		}
		conns[uriKey] = conn
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
	authDatabase, err := appmongodbauth.NewDatabase(
		mongodbClient,
		mongoDbName,
		userClient,
	)

	// Create token validator
	tokenValidator, err := jwtvalidatorgrpc.NewDefaultTokenValidator(
		authDatabase,
		nil,
	)
	if err != nil {
		panic(err)
	}

	// Create JWT validator with ED25519 public key
	jwtValidator, err := commonjwtvalidator.NewEd25519Validator(
		[]byte(jwtKeys[appjwt.PublicKey]),
		tokenValidator,
		commonflag.Mode,
	)
	if err != nil {
		panic(err)
	}

	// Create the JWT issuer with ED25519 private key
	jwtIssuer, err := commonjwtissuer.NewEd25519Issuer([]byte(jwtKeys[appjwt.PrivateKey]))
	if err != nil {
		panic(err)
	}

	// Create server authentication interceptor
	serverAuthInterceptor, err := serverauth.NewInterceptor(
		jwtValidator,
		&pbconfigauth.Interceptions,
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
	serverValidator := commongrpcvalidator.NewDefaultValidator(commonflag.Mode)

	// Create the gRPC auth server validator
	authServerValidator, err := authservervalidator.NewValidator(
		authDatabase,
		serverValidator,
	)
	if err != nil {
		panic(err)
	}

	// Create the gRPC Auth Server
	authServer := authserver.NewServer(
		authDatabase,
		userClient,
		jwtIssuer,
		jwtTokensDuration,
		applogger.AuthServer,
		nil,
		authServerValidator,
		applogger.JwtValidator,
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
	applogger.Listener.ServerStarted(servicePort.Port)
	if err = s.Serve(portListener); err != nil {
		panic(commonlistener.FailedToServeError)
	}
	defer s.Stop()
}
