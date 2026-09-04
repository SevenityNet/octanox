package octanox

import (
	"context"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

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

// Re-exports kept for backwards compatibility; they remain available forever.
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
	// useCookieAuth makes the TypeScript generator emit credentials: 'include' in fetch calls.
	useCookieAuth bool
	// Timeouts carry the app-configured value; an env override, when present, always wins.
	shutdownTimeout   timeout
	readHeaderTimeout timeout
	idleTimeout       timeout
	bodyIdleTimeout   timeout
	bodyDrainGrace    timeout
}

// New returns the singleton Instance, creating it if needed; call Run() to start the runtime.
func New() *Instance {
	if Current != nil {
		return Current
	}

	ginEngine := gin.New()

	Current = &Instance{
		SubRouter:         router.NewSubRouter(&ginEngine.RouterGroup),
		Gin:               ginEngine,
		hooks:             make(map[hook.Hook][]func(*Instance)),
		errorHandlers:     make([]func(error), 0),
		isDebug:           gin.Mode() == gin.DebugMode,
		isDryRun:          os.Getenv("NOX__DRY_RUN") == "true",
		routes:            make([]router.Route, 0),
		serializers:       serialize.NewRegistry(),
		shutdownTimeout:   newTimeout("NOX__SHUTDOWN_TIMEOUT", 30*time.Second),
		readHeaderTimeout: newTimeout("NOX__READ_HEADER_TIMEOUT", 30*time.Second),
		idleTimeout:       newTimeout("NOX__IDLE_TIMEOUT", 120*time.Second),
		bodyIdleTimeout:   newTimeout("NOX__BODY_IDLE_TIMEOUT", 60*time.Second),
		bodyDrainGrace:    newTimeout("NOX__BODY_DRAIN_GRACE", 2*time.Second),
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

	// First in the chain so every later rejection, auth included, still leaves the body bounded.
	Current.Gin.Use(middleware.RequestBodyDeadlineFunc(func() (time.Duration, time.Duration) {
		return Current.bodyIdleTimeout.effective(), Current.bodyDrainGrace.effective()
	}))
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

// ExtraCORSHeaders appends app-specific headers to the default CORS allow/expose lists; call before Serve.
func (i *Instance) ExtraCORSHeaders(allow []string, expose []string) *Instance {
	middleware.ExtraCORSHeaders(allow, expose)
	return i
}

// SetShutdownTimeout sets the HTTP drain timeout (default 30s); NOX__SHUTDOWN_TIMEOUT overrides it when set.
func (i *Instance) SetShutdownTimeout(d time.Duration) *Instance {
	i.shutdownTimeout.value = d
	return i
}

// SetReadHeaderTimeout bounds how long a client may take to send request headers (default 30s); NOX__READ_HEADER_TIMEOUT overrides it when set.
func (i *Instance) SetReadHeaderTimeout(d time.Duration) *Instance {
	i.readHeaderTimeout.value = d
	return i
}

// SetIdleTimeout bounds how long a keep-alive connection may sit idle between requests (default 120s); NOX__IDLE_TIMEOUT overrides it when set.
func (i *Instance) SetIdleTimeout(d time.Duration) *Instance {
	i.idleTimeout.value = d
	return i
}

// SetBodyIdleTimeout bounds how long a request body may stall without progress (default 60s); NOX__BODY_IDLE_TIMEOUT overrides it when set.
func (i *Instance) SetBodyIdleTimeout(d time.Duration) *Instance {
	i.bodyIdleTimeout.value = d
	return i
}

// SetBodyDrainGrace bounds how long net/http may drain a body a handler never finished reading (default 2s); NOX__BODY_DRAIN_GRACE overrides it when set.
func (i *Instance) SetBodyDrainGrace(d time.Duration) *Instance {
	i.bodyDrainGrace.value = d
	return i
}

type timeout struct {
	value time.Duration
	env   time.Duration
}

func newTimeout(envName string, def time.Duration) timeout {
	return timeout{value: def, env: envSeconds(envName)}
}

// Env wins over the app-configured value so an operator can retune a deployment without a rebuild.
func (t timeout) effective() time.Duration {
	if t.env > 0 {
		return t.env
	}
	return t.value
}

// Positive whole seconds only; anything else, including a value that would overflow a Duration, reads as unset.
func envSeconds(name string) time.Duration {
	if t := os.Getenv(name); t != "" {
		if secs, err := strconv.ParseInt(t, 10, 64); err == nil && secs > 0 && secs <= int64(math.MaxInt64/time.Second) {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// Run starts the Octanox runtime. This function will block the current goroutine.
func (i *Instance) Run() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("Starting Octanox...")
	srv := i.startServer()

	<-ctx.Done()

	log.Println("Shutting down...")
	i.emitHook(hook.Hook_Shutdown)

	drainCtx, drainCancel := context.WithTimeout(context.Background(), i.shutdownTimeout.effective())
	defer drainCancel()

	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	} else {
		log.Println("HTTP server drained successfully")
	}

	i.emitHook(hook.Hook_AfterShutdown)
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

// No ReadTimeout or WriteTimeout: both would cancel long streaming handlers; bodies are bounded per request by RequestBodyDeadline instead.
func (i *Instance) newServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           i.Gin,
		ReadHeaderTimeout: i.readHeaderTimeout.effective(),
		IdleTimeout:       i.idleTimeout.effective(),
	}
}

func (i *Instance) startServer() *http.Server {
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
		return nil
	}

	i.emitHook(hook.Hook_Start)

	addr := resolveAddr()
	srv := i.newServer(addr)

	go func() {
		log.Printf("Listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	return srv
}

func resolveAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		if _, err := strconv.Atoi(port); err == nil {
			return ":" + port
		}
		return port
	}
	return ":8080"
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

// Bearer plugs a BearerAuthenticator (JWT signed with secret, 1-day expiry) into the instance, registering routes under basePath.
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

// BearerOAuth2 plugs an OAuth2BearerAuthenticator into the instance; domain must include any prefix and have no trailing slash.
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
