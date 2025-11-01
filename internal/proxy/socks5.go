// Package proxy contains the SOCKS5 proxy implementation.
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/dns"
	"proxy-gateway/internal/policy"
	"strings"

	"github.com/armon/go-socks5"
	zlog "github.com/rs/zerolog/log"
)

// SOCKS5Proxy implements the Proxy interface for SOCKS5 services.
type SOCKS5Proxy struct {
	name   string
	server *socks5.Server
	addr   string
}

// NewSOCKS5Proxy creates and configures a new SOCKS5Proxy instance.
func NewSOCKS5Proxy(cfg config.ProxyConfig, pe *policy.Engine, resolver *dns.Resolver) (*SOCKS5Proxy, error) {
	proxyLogger := zlog.Logger.With().Str("proxy_name", cfg.Name).Str("protocol", "socks5").Logger()
	stdLogger := log.New(proxyLogger, "", 0)
	conf := &socks5.Config{
		Logger:   stdLogger,
		Resolver: resolver,
	}
	if cfg.Auth.Enabled && len(cfg.Auth.Users) > 0 {
		creds := &Argon2Credentials{
			Users:     make(map[string]string),
			ProxyName: cfg.Name,
		}
		for _, user := range cfg.Auth.Users {
			if user.Username == "" || user.Password == "" {
				return nil, fmt.Errorf("user entry in config is missing username or password hash for proxy '%s'", cfg.Name)
			}
			creds.Users[user.Username] = user.Password
		}
		authenticator := socks5.UserPassAuthenticator{Credentials: creds}
		conf.AuthMethods = []socks5.Authenticator{authenticator}
		zlog.Info().Str("proxy_name", cfg.Name).Int("user_count", len(creds.Users)).Msg("SOCKS5 Argon2 authentication enabled")
	} else {
		zlog.Warn().Str("proxy_name", cfg.Name).Msg("SOCKS5 authentication is disabled")
	}
	if pe != nil {
		conf.Rules = &PolicyRule{engine: pe, name: cfg.Name}
	}
	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}
	return &SOCKS5Proxy{
		name:   cfg.Name,
		server: server,
		addr:   cfg.ListenAddress,
	}, nil
}

// Name returns the name of the proxy.
func (p *SOCKS5Proxy) Name() string { return p.name }

// Start starts the SOCKS5 proxy server.
func (p *SOCKS5Proxy) Start(ctx context.Context) error {
	zlog.Info().Str("proxy_name", p.name).Str("address", p.addr).Msg("Starting SOCKS5 proxy")
	listener, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 failed to listen on %s: %w", p.addr, err)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	if err := p.server.Serve(listener); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		return err
	}
	return nil
}

// PolicyRule implements the socks5.Rule interface to enforce policies.
type PolicyRule struct {
	engine *policy.Engine
	name   string
}

// Allow checks if a SOCKS5 request is allowed by the policy engine.
func (r *PolicyRule) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	clientIPStr, _, err := net.SplitHostPort(req.RemoteAddr.String())
	if err != nil {
		zlog.Warn().Err(err).Str("proxy_name", r.name).Str("remote_addr", req.RemoteAddr.String()).Msg("Could not parse client IP")
		return ctx, false
	}
	clientIP := net.ParseIP(clientIPStr)

	clientHostnames, err := net.LookupAddr(clientIPStr)
	if err != nil {
		zlog.Debug().Err(err).Str("proxy_name", r.name).Str("client_ip", clientIPStr).Msg("Could not perform reverse DNS lookup for client")
	}

	destHost := req.DestAddr.FQDN
	if destHost == "" {
		destHost = req.DestAddr.IP.String()
	}
	action, ruleName := r.engine.Evaluate(r.name, clientIP, clientHostnames, destHost, req.DestAddr.IP, req.DestAddr.Port)
	zlog.Info().
		Str("proxy_name", r.name).Str("protocol", "socks5").Str("client_ip", clientIPStr).
		Str("destination", req.DestAddr.String()).Str("command", commandToString(req.Command)).
		Str("policy_action", string(action)).Str("rule_name", ruleName).Msg("Request evaluated")
	return ctx, action == config.AllowAction
}

// Argon2Credentials implements the socks5.Credentials interface for Argon2 password hashing.
type Argon2Credentials struct {
	Users     map[string]string
	ProxyName string
}

// Valid checks if the provided username and password are valid.
func (a *Argon2Credentials) Valid(username, password string) bool {
	expectedHash, ok := a.Users[username]
	if !ok {
		zlog.Warn().Str("proxy_name", a.ProxyName).Str("username", username).Msg("Authentication failed: user not found")
		return false
	}
	match, err := VerifyPassword(password, expectedHash)
	if err != nil {
		zlog.Error().Err(err).Str("proxy_name", a.ProxyName).Str("username", username).Msg("Password verification failed: internal error")
		return false
	}
	if !match {
		zlog.Warn().Str("proxy_name", a.ProxyName).Str("username", username).Msg("Authentication failed: invalid password")
		return false
	}
	zlog.Info().Str("proxy_name", a.ProxyName).Str("username", username).Msg("User authenticated successfully")
	return true
}

// commandToString converts a SOCKS5 command to a string.
func commandToString(cmd uint8) string {
	switch cmd {
	case socks5.ConnectCommand:
		return "CONNECT"
	case socks5.BindCommand:
		return "BIND"
	case socks5.AssociateCommand:
		return "UDP_ASSOCIATE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", cmd)
	}
}
