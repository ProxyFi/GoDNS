package godns

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// LogLevelMap maps log level strings to their integer constants.
// The constants are defined below to ensure type safety and clarity.
var LogLevelMap = map[string]int{
	"DEBUG":  log.LevelDebug,
	"INFO":   log.LevelInfo,
	"NOTICE": log.LevelNotice,
	"WARN":   log.LevelWarn,
	"ERROR":  log.LevelError,
}

// Settings holds all application-wide configuration.
// It is the root struct for the TOML configuration file.
type Settings struct {
	Version      string
	Debug        bool
	Server       DNSServerSettings `toml:"server"`
	ResolvConfig ResolvSettings    `toml:"resolv"`
	Redis        RedisSettings     `toml:"redis"`
	Memcache     MemcacheSettings  `toml:"memcache"`
	Log          LogSettings       `toml:"log"`
	Cache        CacheSettings     `toml:"cache"`
	Hosts        HostsSettings     `toml:"hosts"`
	Blocklist    BlocklistSettings `toml:"blocklist"`
}

// ResolvSettings holds resolver-specific configuration.
type ResolvSettings struct {
	Timeout        int
	Interval       int
	SetEDNS0       bool
	ServerListFile string `toml:"server-list-file"`
	ResolvFile     string `toml:"resolv-file"`
	DNSSECEnable   bool   `toml:"dnssec-enable"`
	TrustAnchorFile string `toml:"trust-anchor-file"`
}

// DNSServerSettings holds DNS server-specific configuration.
type DNSServerSettings struct {
	Host string
	Port int
}

// RedisSettings holds Redis connection configuration.
type RedisSettings struct {
	Addr     string
	Password string
	DB       int
}

// MemcacheSettings holds Memcache connection configuration.
type MemcacheSettings struct {
	Servers []string
}

// LogSettings holds log configuration.
type LogSettings struct {
	Stdout bool
	File   string
	Level  string
}

// LogLevel returns the integer constant for the configured log level.
// It performs a lookup on the LogLevelMap and panics on an invalid level.
// This design choice is carried over from the original code.
func (ls LogSettings) LogLevel() int {
	level, ok := LogLevelMap[ls.Level]
	if !ok {
		// Use fmt.Errorf to create a structured error message and then panic.
		// This is a common pattern for handling critical configuration errors.
		panic(fmt.Errorf("config error: invalid log level '%s'", ls.Level))
	}
	return level
}

// CacheSettings holds cache configuration.
type CacheSettings struct {
	Backend  string
	Expire   int
	Maxcount int
}

// HostsSettings holds hosts file configuration.
type HostsSettings struct {
	Enable          bool
	HostsFile       string `toml:"host-file"`
	RedisEnable     bool   `toml:"redis-enable"`
	RedisKey        string `toml:"redis-key"`
	TTL             uint32 `toml:"ttl"`
	RefreshInterval uint32 `toml:"refresh-interval"`
}

// BlocklistSettings holds blocklist configuration.
type BlocklistSettings struct {
	Enable          bool
	Backend         string
	File            string
	WhitelistFile   string `toml:"whitelist-file"`
	RefreshInterval int    `toml:"refresh-interval"`
	RedisEnable     bool   `toml:"redis-enable"`
	RedisKey        string `toml:"redis-key"`
	RedisWhitelistKey string `toml:"redis-whitelist-key"`
	TTL             uint32
}

// Global variable to hold the application's configuration.
// It is populated by the `init` function.
var settings Settings

// init is a special Go function that runs automatically before `main`.
// It is used here to parse command-line flags and load the configuration file.
func init() {
	var configFile string
	var verbose bool

	// Define command-line flags for the configuration file path and verbosity.
	flag.StringVar(&configFile, "c", "./etc/godns.conf", "Path to the godns toml-formatted config file")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging (sets log level to DEBUG)")

	// Parse the command-line flags.
	flag.Parse()

	// Decode the TOML configuration file into the global settings variable.
	// We use a clean file path directly from the flag.
	if _, err := toml.DecodeFile(configFile, &settings); err != nil {
		// Use a more idiomatic and robust way to handle errors.
		// fmt.Fprintf is used to print to standard error (os.Stderr).
		// This separates log output from standard output, which is a good practice.
		fmt.Fprintf(os.Stderr, "godns: toml decode file failed: %v\n", err)
		os.Exit(1)
	}

	// Override the log level to DEBUG if the -v flag is set.
	// This logic is preserved from the original code.
	if verbose {
		settings.Log.Level = "DEBUG"
	}
}
