package octanox

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/gin-gonic/gin"

	_ "github.com/joho/godotenv/autoload"
)

// Current is the current instance of the Octanox framework. Can be nil if no instance has been created.
var Current *Instance

// Instance is a struct that represents an instance of the Octanox framework.
type Instance struct {
	*SubRouter
	// Gin is the underlying Gin engine that powers the Octanox framework's web server.
	Gin *gin.Engine
	// Authenticator is the underlying authenticator that powers the Octanox framework's authentication operations. Can be nil if no authenticator has been created.
	Authenticator     Authenticator
	authLoginBasePath string
	// hooks is a map of hooks to their respective functions.
	hooks map[Hook][]func(*Instance)
	// errorHandlers is a list of error handlers that can be called when an error occurs.
	errorHandlers []func(error)
	// isDebug is a flag that indicates whether the Octanox framework is running in debug mode.
	isDebug bool
	// isDryRun is a flag that indicates whether the Octanox framework is running in dry-run mode.
	isDryRun bool
	// routes is a list of routes that have been registered in the Octanox framework.
	routes []route
	// serializers is a map of serializers to their respective functions.
	serializers serializerRegistry
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
		SubRouter: &SubRouter{
			gin: &ginEngine.RouterGroup,
		},
		Gin:           ginEngine,
		hooks:         make(map[Hook][]func(*Instance)),
		errorHandlers: make([]func(error), 0),
		isDebug:       gin.Mode() == gin.DebugMode,
		isDryRun:      os.Getenv("NOX__DRY_RUN") == "true",
		routes:        make([]route, 0),
		serializers:   make(serializerRegistry),
	}

	Current.emitHook(Hook_Init)

	Current.Gin.Use(cors())
	Current.Gin.Use(logger())
	Current.Gin.Use(recovery())
	Current.Gin.Use(errorCollectorToHandler())

	return Current
}

// Hook registers a hook function to be called at a specific point in the Octanox runtime.
func (i *Instance) Hook(hook Hook, f func(*Instance)) {
	if _, ok := i.hooks[hook]; !ok {
		i.hooks[hook] = make([]func(*Instance), 0)
	}

	i.hooks[hook] = append(i.hooks[hook], f)
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
	i.emitHook(Hook_Shutdown)
}

func (i *Instance) emitHook(hook Hook) {
	if hooks, ok := i.hooks[hook]; ok {
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
	i.emitHook(Hook_BeforeStart)

	if i.isDryRun {
		log.Println("Dry-run mode enabled. Generating TypeScript code...")
		i.generateTypeScriptClientCode(os.Getenv("NOX__CLIENT_DIR"), i.routes)
		log.Println("TypeScript code generated successfully.")
		os.Exit(0)
		return
	}

	i.emitHook(Hook_Start)

	i.Gin.Run()
}
