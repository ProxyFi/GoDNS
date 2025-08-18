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
	"DEBUG": log.LevelDebug,
	"INFO": log.LevelInfo,
	"NOTICE": log.LevelNotice,
	"WARN": log.LevelWarn,
	"ERROR": log.LevelError,
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
	Timeout                      int
	Interval                     int
	SetEDNS0                     bool
	ServerListFile               string `toml:"server-list-file"`
	ResolvFile                   string `toml:"resolv-file"`
	DNSSECEnable                 bool   `toml:"dnssec-enable"`
	TrustAnchorFile              string `toml:"trust-anchor-file"`
	Servers                      []string
	EnableLatencyBasedLoadBalancing bool `toml:"enable-latency-based-load-balancing"`
}

// CacheSettings holds cache configuration.
type CacheSettings struct {
	Enable      bool
	Expire      int
	Maxcount    int `toml:"max-count"`
	Type        string
	ShortExpire int `toml:"short-expire"`
}

// MemcacheSettings holds memcache configuration.
type MemcacheSettings struct {
	Servers []string
}

// HostsSettings holds hosts configuration.
type HostsSettings struct {
	HostsFile       string `toml:"hosts-file"`
	RedisEnable     bool   `toml:"redis-enable"`
	RedisKey        string `toml:"redis-key"`
	RedisWhitelistKey string `toml:"redis-whitelist-key"`
	RefreshInterval int    `toml:"refresh-interval"`
	TTL             uint32
}

// BlocklistSettings holds blocklist configuration.
type BlocklistSettings struct {
	BlocklistFile string `toml:"blocklist-file"`
	AllowlistFile string `toml:"allowlist-file"`
	Interval      int
	RedisEnable     bool   `toml:"redis-enable"`
	RedisKey        string `toml:"redis-key"`
	RedisWhitelistKey string `toml:"redis-whitelist-key"`
	TTL             uint32
}

// RedisSettings holds Redis configuration.
type RedisSettings struct {
	Addr     string
	Password string
	DB       int
}

// DNSServerSettings holds DNS server configuration.
type DNSServerSettings struct {
	Host string
	Port int
}

// LogSettings holds logging configuration.
type LogSettings struct {
	Stdout   bool
	File     string
	Level    string
}

// LogLevel returns the integer representation of the log level string.
func (l *LogSettings) LogLevel() int {
	level, ok := LogLevelMap[l.Level]
	if !ok {
		return log.LevelInfo // Default to INFO level if not specified.
	}
	return level
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
	if verbose {
		settings.Log.Level = "DEBUG"
	}
}
