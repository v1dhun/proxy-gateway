// Package config provides the structure and validation for the gateway's configuration file.
package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

// configMutex protects the config file from concurrent read/write operations.
var configMutex sync.Mutex

// LogLevel defines the logging level.
type LogLevel string

const (
	// LogLevelDebug is the debug log level.
	LogLevelDebug LogLevel = "debug"
	// LogLevelInfo is the info log level.
	LogLevelInfo LogLevel = "info"
	// LogLevelWarn is the warn log level.
	LogLevelWarn LogLevel = "warn"
	// LogLevelError is the error log level.
	LogLevelError LogLevel = "error"
	// LogLevelFatal is the fatal log level.
	LogLevelFatal LogLevel = "fatal"
	// LogLevelPanic is the panic log level.
	LogLevelPanic LogLevel = "panic"
)

// TLSConfig holds the automatic TLS certificate configuration using ACME.
type TLSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Domain       string `yaml:"domain"`
	Email        string `yaml:"email"`
	CacheDir     string `yaml:"cache_dir"`
	DirectoryURL string `yaml:"directory_url,omitempty"`
	RootCA       string `yaml:"root_ca,omitempty"`
}

// SelfSignedTLSConfig holds the configuration for generating a self-signed TLS cert.
type SelfSignedTLSConfig struct {
	Enabled   bool     `yaml:"enabled"`
	CertPath  string   `yaml:"cert_path"`
	KeyPath   string   `yaml:"key_path"`
	Hostnames []string `yaml:"hostnames"`
}

// Config is the top-level structure mapping to config.yaml.
type Config struct {
	LogLevel         LogLevel            `yaml:"log_level"`
	WebAddress       string              `yaml:"web_address"`
	SessionDBPath    string              `yaml:"session_db_path,omitempty"`
	SessionSecretKey string              `yaml:"session_secret_key"`
	TLS              TLSConfig           `yaml:"tls"`
	SelfSigned       SelfSignedTLSConfig `yaml:"self_signed"`
	DNS              DNSConfig           `yaml:"dns"`
	Proxies          []ProxyConfig       `yaml:"proxies"`
	OIDC             OIDCConfig          `yaml:"oidc"`
	Groups           []Group             `yaml:"groups"`
	TrustedOrigins   []string            `yaml:"trusted_origins,omitempty"`
	AllowedEmails    []string            `yaml:"allowed_emails,omitempty"`
}

// Group defines a group of clients.
type Group struct {
	Name        string   `yaml:"name"`
	ClientIPs   []string `yaml:"client_ips"`
	ClientHosts []string `yaml:"client_hosts"`
}

// OIDCConfig holds the OpenID Connect configuration.
type OIDCConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
}

// DNSConfig holds settings for the internal DNS resolver.
type DNSConfig struct {
	UpstreamServers        []string          `yaml:"upstream_servers"`
	UpstreamServerStrategy string            `yaml:"upstream_server_strategy"`
	QueryTimeout           string            `yaml:"query_timeout"`
	BlockedHosts           []string          `yaml:"blocked_hosts"`
	CustomRecords          map[string]string `yaml:"custom_records"`
	CacheSize              int               `yaml:"cache_size"`
}

// ProxyType defines the type of a proxy.
type ProxyType string

const (
	// HTTPProxy is a proxy for HTTP traffic.
	HTTPProxy ProxyType = "http"
	// SOCKS5Proxy is a proxy for SOCKS5 traffic.
	SOCKS5Proxy ProxyType = "socks5"
	// UDPProxy is a proxy for UDP traffic.
	UDPProxy ProxyType = "udp"
	// MDNSReflector is a proxy for mDNS traffic.
	MDNSReflector ProxyType = "mdns-reflector"
)

// ProxyConfig defines a single proxy instance.
type ProxyConfig struct {
	Name             string    `yaml:"name"`
	Enabled          bool      `yaml:"enabled"`
	Type             ProxyType `yaml:"type"`
	ListenAddress    string    `yaml:"listen_address"`
	ForwardToAddress string    `yaml:"forward_to_address"`
	Interfaces       []string  `yaml:"interfaces"`
	Auth             Auth      `yaml:"auth"`
	Policies         []Policy  `yaml:"policies"`
}

// Auth holds the authentication for a proxy.
type Auth struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Users   []User `yaml:"users"`
}

// User defines a single username/password credential.
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// PolicyAction defines the action to take when a policy matches.
type PolicyAction string

const (
	// AllowAction allows the request.
	AllowAction PolicyAction = "allow"
	// DenyAction denies the request.
	DenyAction PolicyAction = "deny"
)

// Policy defines a single access control rule.
type Policy struct {
	Name       string       `yaml:"name"`
	Action     PolicyAction `yaml:"action"`
	Disabled   bool         `yaml:"disabled,omitempty"`
	Conditions Conditions   `yaml:"conditions"`
}

// DayOfWeek defines a day of the week.
type DayOfWeek string

const (
	Sunday    DayOfWeek = "Sunday"
	Monday    DayOfWeek = "Monday"
	Tuesday   DayOfWeek = "Tuesday"
	Wednesday DayOfWeek = "Wednesday"
	Thursday  DayOfWeek = "Thursday"
	Friday    DayOfWeek = "Friday"
	Saturday  DayOfWeek = "Saturday"
)

// Conditions specify the criteria for a policy to match.
type Conditions struct {
	ClientGroups []string    `yaml:"client_groups"`
	ClientMACs   []string    `yaml:"client_macs"`
	DestHosts    []string    `yaml:"dest_hosts"`
	DestIPs      []string    `yaml:"dest_ips"`
	DestPorts    []int       `yaml:"dest_ports"`
	DaysOfWeek   []DayOfWeek `yaml:"days_of_week"`
	TimeOfDay    string      `yaml:"time_of_day"`
}

// Load reads and validates the YAML configuration file from the given path.
func Load(path string) (*Config, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	configFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config file '%s': %w", path, err)
	}

	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return nil, fmt.Errorf("could not parse config file '%s' as YAML: %w", path, err)
	}

	if err := validate(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Save writes the provided config struct back to the YAML file atomically.
func Save(path string, cfg *Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	if err := validate(cfg); err != nil {
		return fmt.Errorf("validation failed before saving: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("could not marshal config to YAML: %w", err)
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("could not write to temporary config file: %w", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		return fmt.Errorf("could not replace config file: %w", err)
	}

	return nil
}

// validate checks the configuration for logical errors.
func validate(config *Config) error {
	if config.TLS.Enabled && config.SelfSigned.Enabled {
		return fmt.Errorf("tls (ACME) and self_signed are mutually exclusive; please enable only one")
	}

	if config.TLS.Enabled {
		if config.TLS.Domain == "" {
			return fmt.Errorf("tls.domain must be set when tls is enabled")
		}
		if config.TLS.Email == "" {
			return fmt.Errorf("tls.email must be set for ACME registration when tls is enabled")
		}
		if config.TLS.CacheDir == "" {
			return fmt.Errorf("tls.cache_dir must be set to store certificates when tls is enabled")
		}
		if config.TLS.DirectoryURL != "" && config.TLS.RootCA == "" {
			return fmt.Errorf("tls.root_ca must be provided when using a custom tls.directory_url")
		}
	}

	if config.SelfSigned.Enabled {
		if config.SelfSigned.CertPath == "" {
			return fmt.Errorf("self_signed.cert_path must be set when self_signed is enabled")
		}
		if config.SelfSigned.KeyPath == "" {
			return fmt.Errorf("self_signed.key_path must be set when self_signed is enabled")
		}
	}

	if config.OIDC.Enabled {
		if config.OIDC.Issuer == "" {
			return fmt.Errorf("oidc.issuer must be set when oidc is enabled")
		}
		if config.OIDC.ClientID == "" {
			return fmt.Errorf("oidc.client_id must be set when oidc is enabled")
		}
		if config.OIDC.ClientSecret == "" {
			return fmt.Errorf("oidc.client_secret must be set when oidc is enabled")
		}
		if config.OIDC.RedirectURL == "" {
			return fmt.Errorf("oidc.redirect_url must be set when oidc is enabled")
		}
		if len(config.SessionSecretKey) < 32 {
			return fmt.Errorf("session_secret_key must be at least 32 characters long when oidc is enabled")
		}
	}

	for i, p := range config.Proxies {
		if p.Name == "" {
			return fmt.Errorf("proxy at index %d is missing a 'name'", i)
		}
		switch p.Type {
		case HTTPProxy, SOCKS5Proxy, UDPProxy:
			if p.ListenAddress == "" {
				return fmt.Errorf("proxy '%s' is missing 'listen_address'", p.Name)
			}
		case MDNSReflector:
			if len(p.Interfaces) < 2 {
				return fmt.Errorf("proxy '%s' of type 'mdns-reflector' requires at least two 'interfaces'", p.Name)
			}
		case "":
			return fmt.Errorf("proxy '%s' is missing a 'type'", p.Name)
		default:
			return fmt.Errorf("proxy '%s' has an unknown 'type': %s", p.Name, p.Type)
		}
	}
	return nil
}
