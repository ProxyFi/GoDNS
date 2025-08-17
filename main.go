package godns

import (
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"time"

	// The `log` package from our internal library is imported.
	// It provides a global logger instance and helper functions
	// for logging across the application.
	"github.com/ProxyFi/GoDNS/internal/log"
)

// main is the entry point of the GoDNS application.
// It initializes the logger, starts the DNS server, and
// handles graceful shutdown via OS signals.
func main() {

	// Initialize our custom logger from the `internal/log` package.
	initLogger()

	// Create and configure a new DNS server instance.
	// Server settings are loaded from a global `settings` object.
	server := &Server{
		host:     settings.Server.Host,
		port:     settings.Server.Port,
		rTimeout: 5 * time.Second, // Timeout for reading requests.
		wTimeout: 5 * time.Second, // Timeout for writing responses.
	}

	// Start the DNS server. This will typically run in its own goroutine
	// and block until a signal is received to stop it.
	server.Run()

	// Log a message indicating that the server has started successfully.
	log.Info("godns %s start", settings.Version)

	// If debug mode is enabled in the settings, start profiling
	// the application's CPU and memory usage.
	if settings.Debug {
		go profileCPU()
		go profileMEM()
	}

	// Create a channel to listen for OS signals.
	sig := make(chan os.Signal, 1)

	// Notify the signal channel when an interrupt signal (e.g., Ctrl+C) is received.
	signal.Notify(sig, os.Interrupt)

	// The `forever` loop keeps the main goroutine alive until a signal is received.
	// This prevents the program from exiting immediately after starting the server.
forever:
	for {
		select {
		case <-sig:
			// Log a message when a signal is received, indicating that
			// the server is shutting down.
			log.Info("signal received, stopping")
			// Break the loop to allow the `main` function to exit.
			break forever
		}
	}
}

// profileCPU starts CPU profiling for a specified duration and writes the
// profile data to a file named `godns.cprof`.
func profileCPU() {
	// Create the output file for the CPU profile.
	f, err := os.Create("godns.cprof")
	if err != nil {
		log.Error("Failed to create CPU profile file: %s", err)
		return
	}
	// Defer the closing of the file to ensure it's closed even if errors occur.
	defer f.Close()

	// Start CPU profiling.
	pprof.StartCPUProfile(f)

	// Schedule a function to run after 6 minutes to stop the profiling.
	time.AfterFunc(6*time.Minute, func() {
		pprof.StopCPUProfile()
		log.Info("CPU profiling stopped and saved to godns.cprof")
	})
}

// profileMEM starts memory profiling after a specified delay and writes the
// heap profile to a file named `godns.mprof`.
func profileMEM() {
	// Create the output file for the memory profile.
	f, err := os.Create("godns.mprof")
	if err != nil {
		log.Error("Failed to create memory profile file: %s", err)
		return
	}
	// Defer the closing of the file.
	defer f.Close()

	// Schedule a function to run after 5 minutes to write the heap profile.
	time.AfterFunc(5*time.Minute, func() {
		// Get a snapshot of the current heap profile.
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Error("Failed to write memory profile: %s", err)
			return
		}
		log.Info("Memory profiling saved to godns.mprof")
	})
}

// initLogger initializes the application's logging system.
// It configures the console and file handlers based on the application settings.
func initLogger() {
	// The global `log.Logger` instance is already initialized by the `init()`
	// function of the `github.com/ProxyFi/GoDNS/internal/log` package.
	// We do not need to call `NewLogger()` here.

	// Configure the console logger if `settings.Log.Stdout` is enabled.
	if settings.Log.Stdout {
		// Pass `nil` config, as console logging typically has default settings.
		log.Logger.SetLogger("console", nil)
	}

	// Configure the file logger if a log file path is specified.
	if settings.Log.File != "" {
		// Create a configuration map for the file handler.
		config := map[string]interface{}{"file": settings.Log.File}
		log.Logger.SetLogger("file", config)
	}

	// Set the global log level for the application.
	log.Logger.SetLevel(settings.Log.LogLevel())
}

// init is a special Go function that runs automatically before `main`.
// It sets the maximum number of CPUs to use for parallel execution.
func init() {
	// Set GOMAXPROCS to the number of logical CPUs on the machine.
	// This allows the Go scheduler to use all available cores.
	runtime.GOMAXPROCS(runtime.NumCPU())
}
