package godns

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

var (
	settings Settings
)

// LogLevelMap maps log level strings to their integer constants.
var LogLevelMap = map[string]int{
	"DEBUG":  LevelDebug,
	"INFO":   LevelInfo,
	"NOTICE": LevelNotice,
	"WARN":   LevelWarn,
	"ERROR":  LevelError,
}

// Settings holds all application-wide configuration.
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
	// BlocklistSettings added to support blocklist configuration.
	Blocklist BlocklistSettings `toml:"blocklist"`
}

// ResolvSettings holds resolver-specific configuration.
type ResolvSettings struct {
	Timeout        int
	Interval       int
	SetEDNS0       bool
	ServerListFile string `toml:"server-list-file"`
	ResolvFile     string `toml:"resolv-file"`
}

// DNSServerSettings holds DNS server-specific configuration.
type DNSServerSettings struct {
	Host string
	Port int
}

// RedisSettings holds Redis connection configuration.
type RedisSettings struct {
	Host     string
	Port     int
	DB       int
	Password string
}

// MemcacheSettings holds Memcache connection configuration.
type MemcacheSettings struct {
	Servers []string
}

// Addr returns the Redis server address string.
func (s RedisSettings) Addr() string {
	return s.Host + ":" + strconv.Itoa(s.Port)
}

// LogSettings holds logging configuration.
type LogSettings struct {
	Stdout bool
	File   string
	Level  string
}

// LogLevel converts a log level string to its integer constant.
func (ls LogSettings) LogLevel() int {
	l, ok := LogLevelMap[ls.Level]
	if !ok {
		panic("Config error: invalid log level: " + ls.Level)
	}
	return l
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

// init loads the configuration from file.
func init() {
	var configFile string
	var verbose bool

	flag.StringVar(&configFile, "c", "./etc/godns.conf", "Look for godns toml-formatting config file in this directory")
	flag.BoolVar(&verbose, "v", false, "verbose log")
	flag.Parse()

	_, err := toml.DecodeFile(configFile, &settings)
	if err != nil {
		fmt.Printf("Get config file error %s\n", err.Error())
		os.Exit(2)
	}
	
	if verbose {
		settings.Log.Level = "DEBUG"
	}

	initLogger()
}
