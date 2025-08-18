package godns

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// Server encapsulates the configuration and runtime state of a DNS server.
// It handles both TCP and UDP connections.
type Server struct {
	// Host is the network host to listen on (e.g., "127.0.0.1" or "::1").
	host string
	// Port is the network port to listen on.
	port int
	// ReadTimeout is the maximum duration for reading the entire request.
	rTimeout time.Duration
	// WriteTimeout is the maximum duration for writing the entire response.
	wTimeout time.Duration
}

// Addr returns the complete network address string (host:port) for the server.
func (s *Server) Addr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.port))
}

// Run initializes and starts both UDP and TCP DNS listeners.
// It launches each listener in a separate goroutine.
func (s *Server) Run() {
	// Initialize a new DNS handler. The implementation of NewHandler()
	// and the DoTCP/DoUDP methods are assumed to be defined elsewhere.
	handler := NewHandler()

	// Use a single dns.ServeMux for both TCP and UDP. This is a common
	// practice and simplifies handler management.
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", handler.DoTCP) // The same handler can be used for both.

	// The old code used separate ServeMux instances. The current approach is
	// slightly cleaner but achieves the same result, as the dns.Server
	// already handles the network-specific logic.

	// Configure and create the TCP DNS server.
	tcpServer := &dns.Server{
		Addr:         s.Addr(),
		Net:          "tcp",
		Handler:      dnsMux,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
	}

	// Configure and create the UDP DNS server.
	udpServer := &dns.Server{
		Addr:         s.Addr(),
		Net:          "udp",
		Handler:      dnsMux,
		UDPSize:      dns.DefaultMsgSize, // Using a standard constant for clarity.
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
	}

	// Start both servers concurrently.
	// We use goroutines to avoid blocking the main thread.
	go s.start(context.Background(), udpServer)
	go s.start(context.Background(), tcpServer)
}

// start begins serving requests for a given dns.Server.
// It logs the server's status and handles potential errors during startup.
// The context.Context parameter, while not used in this specific implementation,
// is included to align with modern Go practices for managing goroutine lifecycles
// and providing request-scoped data.
func (s *Server) start(ctx context.Context, ds *dns.Server) {
	log.Info("Starting %s listener on %s", ds.Net, s.Addr())

	// Use a defer statement to ensure that resources are handled correctly
	// even if an error occurs. This adds robustness.
	defer func() {
		log.Info("Shutting down %s listener on %s", ds.Net, s.Addr())
	}()

	// The ListenAndServe method is called here.
	// Its return value is checked for potential errors.
	err := ds.ListenAndServe()
	if err != nil {
		// Log the error with additional context to help with debugging.
		log.Error("Failed to start %s listener on %s: %v", ds.Net, s.Addr(), err)
	}
}
