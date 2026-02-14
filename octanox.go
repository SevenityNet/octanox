package octanox

import (
	"context"
	"log"
	"os"
	"os/signal"
	"reflect"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	_ "github.com/joho/godotenv/autoload"

	"github.com/sevenitynet/octanox/auth"
	"github.com/sevenitynet/octanox/codegen"
	"github.com/sevenitynet/octanox/ctx"
	"github.com/sevenitynet/octanox/hook"
	"github.com/sevenitynet/octanox/middleware"
	"github.com/sevenitynet/octanox/model"
	"github.com/sevenitynet/octanox/request"
	"github.com/sevenitynet/octanox/router"
	"github.com/sevenitynet/octanox/serialize"
)

// Re-exports for backwards compatibility.
// These types are re-exported for convenience and will remain available forever.
type (
	// User is the interface that defines the authenticated user model.
	User = model.User

	// Context is a type that represents a generic context.
	Context = ctx.Context

	// SubRouter is a struct that represents a router in the Octanox framework.
	SubRouter = router.SubRouter

	// OAuth2UserProvider is an interface for OAuth2 user providers.
	OAuth2UserProvider = auth.OAuth2UserProvider

	// Request types - embedded in handler request structs
	GetRequest    = request.GetRequest
	PostRequest   = request.PostRequest
	PutRequest    = request.PutRequest
	DeleteRequest = request.DeleteRequest
	PatchRequest  = request.PatchRequest
)

// Current is the current instance of the Octanox framework. Can be nil if no instance has been created.
var Current *Instance

// Instance is a struct that represents an instance of the Octanox framework.
type Instance struct {
	*router.SubRouter
	// Gin is the underlying Gin engine that powers the Octanox framework's web server.
	Gin *gin.Engine
	// Authenticator is the underlying authenticator that powers the Octanox framework's authentication operations. Can be nil if no authenticator has been created.
	Authenticator     auth.Authenticator
	authLoginBasePath string
	// hooks is a map of hooks to their respective functions.
	hooks map[hook.Hook][]func(*Instance)
	// errorHandlers is a list of error handlers that can be called when an error occurs.
	errorHandlers []func(error)
	// isDebug is a flag that indicates whether the Octanox framework is running in debug mode.
	isDebug bool
	// isDryRun is a flag that indicates whether the Octanox framework is running in dry-run mode.
	isDryRun bool
	// routes is a list of routes that have been registered in the Octanox framework.
	routes []router.Route
	// serializers is a map of serializers to their respective functions.
	serializers serialize.Registry
	// useCookieAuth is a flag that indicates whether cookie-based authentication is enabled.
	// This is used by the TypeScript code generator to include credentials: 'include' in fetch calls.
	useCookieAuth bool
}

// New creates a new instance of the Octanox framework. If an instance already exists, it will return the existing instance.
// This won't start the Octanox runtime, you need to call Run() on the instance to start the runtime.
func New() *Instance {
	if Current != nil {
		return Current
	}

	ginEngine := gin.New()

	Current = &Instance{
		SubRouter: router.NewSubRouter(&ginEngine.RouterGroup),
		Gin:       ginEngine,
		hooks:     make(map[hook.Hook][]func(*Instance)),
		errorHandlers: make([]func(error), 0),
		isDebug:       gin.Mode() == gin.DebugMode,
		isDryRun:      os.Getenv("NOX__DRY_RUN") == "true",
		routes:        make([]router.Route, 0),
		serializers:   serialize.NewRegistry(),
	}

	// Wire up function variables to break circular dependencies
	router.IsDryRunFunc = func() bool { return Current.isDryRun }
	router.AddRouteFunc = func(r router.Route) { Current.routes = append(Current.routes, r) }
	router.HasAuthenticatorFunc = func() bool { return Current.Authenticator != nil }
	router.AuthenticateFunc = func(c *gin.Context) (model.User, error) {
		if Current.Authenticator != nil {
			return Current.Authenticator.Authenticate(c)
		}
		return nil, nil
	}
	router.SerializeFunc = func(obj interface{}, c ctx.Context) interface{} {
		return Current.Serialize(obj, c)
	}

	request.IsDebugFunc = func() bool { return Current.isDebug }

	middleware.EmitErrorFunc = func(err error) { Current.emitError(err) }

	Current.emitHook(hook.Hook_Init)

	Current.Gin.Use(middleware.CORS())
	Current.Gin.Use(middleware.SecurityHeaders())
	Current.Gin.Use(middleware.Logger())
	Current.Gin.Use(middleware.Recovery())
	Current.Gin.Use(middleware.ErrorCollector())

	return Current
}

// Hook registers a hook function to be called at a specific point in the Octanox runtime.
func (i *Instance) Hook(h hook.Hook, f func(*Instance)) {
	if _, ok := i.hooks[h]; !ok {
		i.hooks[h] = make([]func(*Instance), 0)
	}

	i.hooks[h] = append(i.hooks[h], f)
}

// ErrorHandler registers an error handler function to be called when an error occurs in the Octanox runtime.
func (i *Instance) ErrorHandler(f func(error)) {
	i.errorHandlers = append(i.errorHandlers, f)
}

// Run starts the Octanox runtime. This function will block the current goroutine. If any error occurs, it will panic.
func (i *Instance) Run() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Println("Starting Octanox...")
	go i.runInternally()

	<-ctx.Done()

	log.Println("Shutting down...")
	i.emitHook(hook.Hook_Shutdown)
}

func (i *Instance) emitHook(h hook.Hook) {
	if hooks, ok := i.hooks[h]; ok {
		for _, f := range hooks {
			f(Current)
		}
	}
}

func (i *Instance) emitError(err error) {
	for _, f := range i.errorHandlers {
		f(err)
	}
}

func (i *Instance) runInternally() {
	i.emitHook(hook.Hook_BeforeStart)

	if i.isDryRun {
		log.Println("Dry-run mode enabled. Generating TypeScript code...")

		var authMethod *auth.AuthenticationMethod
		if i.Authenticator != nil {
			m := i.Authenticator.Method()
			authMethod = &m
		}

		codegen.GenerateTypeScriptClient(os.Getenv("NOX__CLIENT_DIR"), i.routes, codegen.TSConfig{
			UseCookieAuth: i.useCookieAuth,
			AuthMethod:    authMethod,
		})
		log.Println("TypeScript code generated successfully.")
		os.Exit(0)
		return
	}

	i.emitHook(hook.Hook_Start)

	i.Gin.Run()
}

// Serialize serializes an object into another form using the registered serializers.
func (i *Instance) Serialize(obj interface{}, c ctx.Context) any {
	return i.serializers.Serialize(obj, c)
}

// RegisterSerializer is a function that registers a serializer for a given type.
func (i *Instance) RegisterSerializer(obj interface{}, serializer interface{}) *Instance {
	typeOfObj := reflect.TypeOf(obj)
	if _, ok := i.serializers[typeOfObj]; ok {
		panic("octanox: serializer for type " + typeOfObj.String() + " already registered")
	}

	ftype := reflect.ValueOf(serializer)
	i.serializers[typeOfObj] = func(obj interface{}, c ctx.Context) any {
		return ftype.Call([]reflect.Value{reflect.ValueOf(obj), reflect.ValueOf(c)})[0].Interface()
	}

	return i
}

// AuthenticatorBuilder is a struct that helps build the Authenticator.
type AuthenticatorBuilder struct {
	instance *Instance
	provider interface{}
}

// Authenticate plugs in the authentication module into Octanox.
func (i *Instance) Authenticate(provider interface{}) *AuthenticatorBuilder {
	if i.Authenticator != nil {
		panic("octanox: authenticator already exists")
	}

	return &AuthenticatorBuilder{i, provider}
}

// Bearer creates a new BearerAuthenticator with the given secret and plugs it into the Authenticator.
// The basePath is the base path for the authentication routes.
// The secret is the secret key used to sign the JWT token.
// Defaults to 1 day for the token expiration time.
func (b *AuthenticatorBuilder) Bearer(secret, basePath string) *auth.BearerAuthenticator {
	userProvider, ok := b.provider.(auth.UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	bearer := auth.NewBearerAuthenticator(userProvider, secret)
	bearer.RegisterRoutes(b.instance.Gin.Group(basePath))

	b.instance.Authenticator = bearer
	b.instance.authLoginBasePath = basePath

	return bearer
}

// BearerOAuth2 creates a new OAuth2BearerAuthenticator with the given OAuth2 parameters and plugs it into the Authenticator.
// The basePath is the base path for the authentication routes.
// The clientId is the OAuth2 client ID.
// The clientSecret is the OAuth2 client secret.
// The oauth2Endpoint is the OAuth2 endpoint.
// The scopes is the list of scopes to request.
// The domain is the domain of this application. The domain must not have a trailing slash. The domain should contain any prefix
// The loginSuccessRedirect is the URL to redirect to after a successful login.
// The secret is the secret key used to sign the JWT token.
func (b *AuthenticatorBuilder) BearerOAuth2(oauth2Endpoint oauth2.Endpoint, scopes []string, clientId, clientSecret, domain, loginSuccessRedirect, secret, basePath string) *auth.OAuth2BearerAuthenticator {
	userProvider, ok := b.provider.(auth.OAuth2UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected OAuth2UserProvider")
	}

	bearer := auth.NewOAuth2BearerAuthenticator(auth.OAuth2Config{
		Provider:             userProvider,
		Endpoint:             oauth2Endpoint,
		Scopes:               scopes,
		ClientID:             clientId,
		ClientSecret:         clientSecret,
		Domain:               domain,
		BasePath:             basePath,
		LoginSuccessRedirect: loginSuccessRedirect,
		Secret:               secret,
	})

	// Set callback to track cookie auth in instance
	bearer.SetOnCookieAuthEnabled(func() {
		b.instance.useCookieAuth = true
	})

	bearer.RegisterRoutes(b.instance.Gin.Group(basePath))

	b.instance.Authenticator = bearer
	b.instance.authLoginBasePath = basePath

	return bearer
}

// Basic creates a new BasicAuthenticator and plugs it into the Authenticator.
func (b *AuthenticatorBuilder) Basic() *auth.BasicAuthenticator {
	userProvider, ok := b.provider.(auth.UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	basic := auth.NewBasicAuthenticator(userProvider)
	b.instance.Authenticator = basic

	return basic
}

// ApiKey creates a new ApiKeyAuthenticator and plugs it into the Authenticator.
func (b *AuthenticatorBuilder) ApiKey() *auth.ApiKeyAuthenticator {
	userProvider, ok := b.provider.(auth.UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	apiKey := auth.NewApiKeyAuthenticator(userProvider)
	b.instance.Authenticator = apiKey

	return apiKey
}
