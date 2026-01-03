package hook

// Hook is the type of a hook function that can be registered within the Octanox framework.
type Hook string

const (
	// Init is a hook that is called when the Octanox runtime is initializing.
	Hook_Init Hook = "init"
	// BeforeStart is a hook that is called when the Octanox runtime is registering its routes just before starting the web server. Here all routes should be registered. Before dry-run checks.
	Hook_BeforeStart Hook = "before_start"
	// Start is a hook that is called when the Octanox runtime is starting. After dry-run checks and before the web server starts.
	Hook_Start Hook = "start"
	// Shutdown is a hook that is called when the Octanox runtime is shutting down.
	Hook_Shutdown Hook = "shutdown"
)
