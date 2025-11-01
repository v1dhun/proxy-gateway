// File: ./cmd/gateway/main.go

// Package main is the entry point for the Proxy Gateway Daemon.
package main

import (
	"context"
	// NEW IMPORTS
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/dns"
	"proxy-gateway/internal/manager"
	"proxy-gateway/internal/policy"
	"proxy-gateway/internal/proxy"
	"proxy-gateway/internal/web"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// sampleConfigYAML is a template for the configuration file.
const sampleConfigYAML = `# -----------------------------------------------------------------------------
# Global Settings for the Proxy Gateway Daemon
# -----------------------------------------------------------------------------
log_level: "info" # Options: "debug", "info", "warn", "error"

# The address for the web UI. Use ":443" for production with TLS.
web_address: "127.0.0.1:8081"

# Path to the SQLite database for web UI sessions.
# If not specified, defaults to "sessions.db" in the current directory.
# This makes user sessions persistent across gateway restarts.
session_db_path: "sessions.db"
# FTL error: key must be 32 or 64 bytes (got 40).  
# Fix: generate a new key with `openssl rand -hex 32` or `openssl rand -hex 64` and update your config.
session_secret_key: "abdec9cc8cacb5ac87f7de5eb6696a5f4a33d36ad28b190e016abf020060db8d"

# -----------------------------------------------------------------------------
# TLS Configuration - CHOOSE ONE METHOD (ACME or Self-Signed)
# -----------------------------------------------------------------------------

# --- Method 1: Automatic Certificate via ACME (Let's Encrypt or Self-Hosted) ---
# Use this for production or services with a real domain name.
# tls:
#   enabled: true
#   domain: "my-gateway.public-domain.com"
#   email: "your-email@public-domain.com"
#   cache_dir: "/var/lib/proxy-gateway/certs"
#   # --- Optional: For Self-Hosted ACME ---
#   # directory_url: "https://step-ca.internal.corp/acme/acme/directory"
#   # root_ca: "/etc/proxy-gateway/certs/root_ca.pem"

# --- Method 2: Automatic Self-Signed Certificate ---
# Use this for local development or testing.
# Your browser will show a security warning which you must accept.
# self_signed:
#   enabled: true
#   cert_path: "server.crt"
#   key_path: "server.key"
#   # Hostnames the certificate will be valid for.
#   hostnames:
#     - "localhost"
#     - "127.0.0.1"

# A list of allowed origins for CSRF protection on the web UI.
# If using any form of TLS, this MUST be your HTTPS origin.
trusted_origins:
  - "http://127.0.0.1:8081"
  # - "https://localhost:8443"

# -----------------------------------------------------------------------------
# OIDC Configuration for Web UI Authentication
# -----------------------------------------------------------------------------
oidc:
  enabled: true # Set to false to disable OIDC login and make the dashboard public.
  issuer: "https://your-oidc-provider.com/"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  # This URL must match a valid callback URL in your OIDC provider settings.
  # If using TLS, this must be an https:// URL.
  redirect_url: "http://127.0.0.1:8081/auth/callback"

# -----------------------------------------------------------------------------
# Web UI Access Control
# -----------------------------------------------------------------------------
# If OIDC is enabled, you can restrict access to a specific list of emails.
# If this list is empty or not present, any authenticated user will be allowed.
# allowed_emails:
#   - "admin@example.com"
#   - "user2@example.com"

# -----------------------------------------------------------------------------
# Global DNS Engine Configuration
# -----------------------------------------------------------------------------
dns:
  # Upstream DNS servers to forward queries to.
  upstream_servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  # Strategy for selecting an upstream server: "round_robin", "random", "fastest".
  upstream_server_strategy: "round_robin"
  # Timeout for upstream DNS queries.
  query_timeout: "2s"
  # A list of hostnames/domains to block. Wildcards (*) are supported.
  blocked_hosts:
    - "*.doubleclick.net"
  # A map of custom DNS records for internal hosts.
  custom_records:
    "gateway.internal": "192.168.1.1"

# -----------------------------------------------------------------------------
# Client Groups
# Used in policies to group clients by IP or hostname.
# -----------------------------------------------------------------------------
groups:
  - name: "trusted-devices"
    client_ips:
      - "192.168.1.100/32"
      - "192.168.1.101/32"
    client_hosts:
      - "laptop.local"

# -----------------------------------------------------------------------------
# Proxy Definitions
# -----------------------------------------------------------------------------
proxies:
  # --- HTTP Proxy Example ---
  - name: "Standard_HTTP_Proxy"
    enabled: true
    type: "http"
    listen_address: "0.0.0.0:8080"
    policies:
      - name: "Allow_Trusted_Devices"
        action: "allow"
        conditions:
          client_groups: ["trusted-devices"]

  # --- SOCKS5 Proxy with Argon2 Authentication ---
  # To generate a password hash, run: ./hash-password
  # - name: "Secure_SOCKS5_Gateway"
  #   enabled: true
  #   type: "socks5"
  #   listen_address: "0.0.0.0:1080"
  #   auth:
  #     enabled: true # Set to false to allow access without a password, even if users are defined.
  #     users:
  #       - username: "myuser"
  #         password: "$argon2id$v=19$m=65536,t=1,p=4$b2PdhQYL0o78xq0nJ07g0w$zp6+FLec+r6tUCSOGlpXVd7GZF3m1LNIlJ+aV657UNc"
  #   policies:
  #     - name: "Allow_All_Authenticated"
  #       action: "allow"
  #       conditions: {} # Empty conditions match all traffic

  # --- Stateful UDP Proxy Example (e.g., for a game server or DNS) ---
  # - name: "DNS_Forwarder"
  #   enabled: true
  #   type: "udp"
  #   listen_address: "0.0.0.0:5300"
  #   forward_to_address: "1.1.1.1:53"
  #   policies:
  #     - name: "Allow_Internal_Network"
  #       action: "allow"
  #       conditions:
  #         client_ips: ["192.168.1.0/24"]

  # --- mDNS Reflector Example (for cross-VLAN service discovery) ---
  # - name: "Cross-Subnet_mDNS"
  #   enabled: true
  #   type: "mdns-reflector"
  #   # Requires at least two network interface names.
  #   interfaces: ["eth0", "eth1"]
`

// main is the entry point for the gateway application.
func main() {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file.")
	webAddress := flag.String("web-addr", "", "Address for the web UI server (e.g., ':8080').")
	generateConfig := flag.Bool("generate-config", false, "Generate a sample config.yaml and exit.")
	flag.Parse()

	if *generateConfig {
		fmt.Print(sampleConfigYAML)
		os.Exit(0)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	initialCfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load or validate initial configuration")
	}

	if *webAddress != "" {
		initialCfg.WebAddress = *webAddress
	}

	configManager := manager.New(initialCfg, *configPath)

	logLevel, err := zerolog.ParseLevel(string(configManager.Get().LogLevel))
	if err != nil {
		logLevel = zerolog.InfoLevel
		log.Warn().Str("configured_level", string(configManager.Get().LogLevel)).Msg("Invalid log level, defaulting to 'info'")
	}
	zerolog.SetGlobalLevel(logLevel)

	dnsResolver, err := dns.NewResolver(configManager.Get().DNS)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize DNS resolver")
	}

	policyEngine := policy.NewEngine(configManager)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	wg.Add(1)
	go manageProxies(ctx, &wg, configManager, policyEngine, dnsResolver)

	if configManager.Get().WebAddress != "" {
		webServer, err := web.NewServer(configManager)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create web server")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info().Msg("Starting web server component")
			if err := webServer.Start(); err != nil {
				if err != http.ErrServerClosed {
					log.Error().Err(err).Msg("Web server failed")
				}
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := webServer.Shutdown(shutdownCtx); err != nil {
				log.Error().Err(err).Msg("Web server graceful shutdown failed")
			}
		}()
	}

	<-ctx.Done()
	stop()
	log.Warn().Msg("Shutdown signal received, waiting for all services to stop...")
	wg.Wait()
	log.Info().Msg("All services stopped. Gateway has shut down gracefully.")
}

// --- START: NEW HELPER CODE ---

// getConfigHash generates a SHA256 hash of a proxy's configuration.
// This is used to detect configuration changes and trigger proxy restarts.
func getConfigHash(proxyCfg config.ProxyConfig) string {
	bytes, err := json.Marshal(proxyCfg)
	if err != nil {
		log.Error().Err(err).Str("proxy_name", proxyCfg.Name).Msg("Failed to marshal proxy config for hashing")
		return ""
	}
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// runningProxyInfo holds information about a running proxy instance.
type runningProxyInfo struct {
	cancel     context.CancelFunc
	configHash string
}

// --- END: NEW HELPER CODE ---

// manageProxies runs a reconciliation loop to start/stop/restart proxies based on the current config.
// It runs in a separate goroutine and periodically checks for configuration changes.
func manageProxies(ctx context.Context, wg *sync.WaitGroup, cm *manager.ConfigManager, pe *policy.Engine, resolver *dns.Resolver) {
	defer wg.Done()

	var mu sync.RWMutex

	runningProxies := make(map[string]runningProxyInfo)
	stoppingProxies := make(map[string]chan struct{})

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Warn().Msg("Proxy manager stopping...")

			mu.RLock()
			for name, pInfo := range runningProxies {
				log.Info().Str("proxy_name", name).Msg("Stopping proxy due to shutdown signal.")
				pInfo.cancel()
			}
			mu.RUnlock()
			return

		case <-ticker.C:
			cfg := cm.Get()

			// Build map of desired proxies
			desiredProxies := make(map[string]string)
			for _, proxyCfg := range cfg.Proxies {
				if proxyCfg.Enabled {
					desiredProxies[proxyCfg.Name] = getConfigHash(proxyCfg)
				}
			}

			// 1️⃣ Stop outdated or removed proxies asynchronously
			mu.Lock()
			for name, pInfo := range runningProxies {
				desiredHash, stillDesired := desiredProxies[name]
				if !stillDesired || pInfo.configHash != desiredHash {
					reason := "config changed"
					if !stillDesired {
						reason = "disabled or removed"
					}
					log.Warn().Str("proxy_name", name).Msgf("Proxy %s — stopping asynchronously...", reason)

					pInfo.cancel()
					done := make(chan struct{})
					stoppingProxies[name] = done
					delete(runningProxies, name)

					go func(proxyName string) {
						defer close(done)
						for {
							time.Sleep(100 * time.Millisecond)
							mu.RLock()
							_, stillRunning := runningProxies[proxyName]
							mu.RUnlock()
							if !stillRunning {
								break
							}
						}
						log.Info().Str("proxy_name", proxyName).Msg("Proxy fully stopped.")
					}(name)
				}
			}
			mu.Unlock()

			// 2️⃣ Start missing proxies (only if not stopping)
			for _, proxyCfg := range cfg.Proxies {
				if !proxyCfg.Enabled {
					continue
				}

				name := proxyCfg.Name

				mu.RLock()
				_, stopping := stoppingProxies[name]
				_, running := runningProxies[name]
				mu.RUnlock()

				if stopping || running {
					continue
				}

				log.Info().Str("proxy_name", name).Msg("Starting proxy...")

				p, err := createProxy(proxyCfg, pe, resolver)
				if err != nil {
					log.Error().Err(err).Str("proxy_name", name).Msg("Failed to create proxy")
					continue
				}

				proxyCtx, cancel := context.WithCancel(ctx)
				newInfo := runningProxyInfo{
					cancel:     cancel,
					configHash: getConfigHash(proxyCfg),
				}

				mu.Lock()
				runningProxies[name] = newInfo
				mu.Unlock()

				wg.Add(1)
				go func(p proxy.Proxy, name string) {
					defer wg.Done()

					log.Info().Str("proxy_name", name).Msg("Proxy started.")
					if err := p.Start(proxyCtx); err != nil {
						log.Error().Err(err).Str("proxy_name", name).Msg("Proxy exited with error.")
					} else {
						log.Info().Str("proxy_name", name).Msg("Proxy stopped gracefully.")
					}

					mu.Lock()
					delete(runningProxies, name)
					delete(stoppingProxies, name)
					mu.Unlock()
				}(p, name)
			}
		}
	}
}

// createProxy is a factory function that constructs a proxy based on its configuration.
func createProxy(proxyCfg config.ProxyConfig, pe *policy.Engine, resolver *dns.Resolver) (proxy.Proxy, error) {
	switch proxyCfg.Type {
	case config.HTTPProxy:
		return proxy.NewHTTPProxy(proxyCfg, pe, resolver), nil
	case config.SOCKS5Proxy:
		return proxy.NewSOCKS5Proxy(proxyCfg, pe, resolver)
	case config.UDPProxy:
		return proxy.NewUDPProxy(proxyCfg, pe), nil
	case config.MDNSReflector:
		return proxy.NewMDNSReflector(proxyCfg), nil
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", proxyCfg.Type)
	}
}
