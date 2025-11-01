// Package dns implements the gateway's internal, policy-aware DNS resolver.
package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"proxy-gateway/internal/config"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	defaultQueryTimeout     = 5 * time.Second
	maxDNSCacheTTL          = 1 * time.Hour
	roundRobinStrategy      = "round_robin"
	randomStrategy          = "random"
	defaultUpstreamStrategy = roundRobinStrategy
)

// Resolver is a custom DNS resolver that applies blocking and custom records.
// It implements the socks5.Resolver interface, making it compatible with SOCKS5 proxies.
type Resolver struct {
	upstreamServers        []string
	upstreamServerStrategy string
	upstreamServerIndex    int
	queryTimeout           time.Duration
	blockedHosts           []glob.Glob
	customRecords          map[string]net.IP
	cache                  *sync.Map
	mu                     sync.Mutex
}

type dnsCacheEntry struct {
	ip      net.IP
	expires time.Time
}

// NewResolver creates a new DNS resolver from the provided configuration.
func NewResolver(cfg config.DNSConfig) (*Resolver, error) {
	queryTimeout := defaultQueryTimeout
	if cfg.QueryTimeout != "" {
		d, err := time.ParseDuration(cfg.QueryTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS query_timeout duration '%s': %w", cfg.QueryTimeout, err)
		}
		queryTimeout = d
	}

	strategy := strings.ToLower(cfg.UpstreamServerStrategy)
	if strategy != roundRobinStrategy && strategy != randomStrategy {
		log.Warn().Str("strategy", cfg.UpstreamServerStrategy).Msg("Invalid upstream_server_strategy, defaulting to round_robin")
		strategy = defaultUpstreamStrategy
	}

	r := &Resolver{
		upstreamServers:        cfg.UpstreamServers,
		upstreamServerStrategy: strategy,
		queryTimeout:           queryTimeout,
		customRecords:          make(map[string]net.IP),
		cache:                  &sync.Map{},
	}

	for _, hostPattern := range cfg.BlockedHosts {
		g, err := glob.Compile(hostPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked_hosts pattern '%s': %w", hostPattern, err)
		}
		r.blockedHosts = append(r.blockedHosts, g)
	}

	for host, ipStr := range cfg.CustomRecords {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP for custom_record '%s'", host)
		}
		r.customRecords[dns.Fqdn(host)] = ip
	}

	r.startCacheCleanup(5 * time.Minute)
	return r, nil
}

// getUpstreamServer selects an upstream server based on the configured strategy.
func (r *Resolver) getUpstreamServer() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	numServers := len(r.upstreamServers)
	if numServers == 0 {
		return "", errors.New("no upstream DNS servers configured")
	}

	switch r.upstreamServerStrategy {
	case randomStrategy:
		return r.upstreamServers[rand.Intn(numServers)], nil
	case roundRobinStrategy:
		server := r.upstreamServers[r.upstreamServerIndex]
		r.upstreamServerIndex = (r.upstreamServerIndex + 1) % numServers
		return server, nil
	default:
		// This should not happen due to the validation in NewResolver, but as a fallback:
		return r.upstreamServers[0], nil
	}
}

// startCacheCleanup runs a goroutine that periodically cleans up expired DNS entries.
func (r *Resolver) startCacheCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			r.cache.Range(func(key, value interface{}) bool {
				if entry, ok := value.(dnsCacheEntry); ok && time.Now().After(entry.expires) {
					r.cache.Delete(key)
					log.Debug().Str("domain", key.(string)).Msg("DNS cache: removed expired entry")
				}
				return true
			})
		}
	}()
}

// Resolve performs a DNS lookup for a given host, handling CNAMEs and retries.
func (r *Resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return r.resolve(ctx, name, 0)
}

// resolve is the internal recursive resolver.
func (r *Resolver) resolve(ctx context.Context, name string, depth int) (context.Context, net.IP, error) {
	if depth > 10 {
		return ctx, nil, fmt.Errorf("DNS resolution for %s exceeded max depth of 10", name)
	}

	fqdn := dns.Fqdn(name)
	log.Debug().Str("domain", name).Int("depth", depth).Msg("DNS resolver: resolving host")

	// 1. Check block list
	for _, g := range r.blockedHosts {
		if g.Match(name) {
			log.Info().Str("domain", name).Msg("DNS resolver: host is blocked by policy")
			return ctx, nil, fmt.Errorf("domain %s is blocked", name)
		}
	}

	// 2. Check custom records (e.g., for local services)
	if ip, ok := r.customRecords[fqdn]; ok {
		log.Info().Str("domain", name).IPAddr("ip", ip).Msg("DNS resolver: answered from custom records")
		return ctx, ip, nil
	}

	// 3. Check cache
	if val, ok := r.cache.Load(fqdn); ok {
		if entry, ok := val.(dnsCacheEntry); ok && time.Now().Before(entry.expires) {
			log.Debug().Str("domain", name).IPAddr("ip", entry.ip).Msg("DNS resolver: answered from cache")
			return ctx, entry.ip, nil
		}
	}

	// 4. Forward to upstream DNS server
	ip, err := r.lookupUpstream(ctx, fqdn, name)
	if err != nil {
		return ctx, nil, err
	}

	return ctx, ip, nil
}

// lookupUpstream queries upstream servers for A and AAAA records.
func (r *Resolver) lookupUpstream(ctx context.Context, fqdn, name string) (net.IP, error) {
	upstreamServer, err := r.getUpstreamServer()
	if err != nil {
		return nil, err
	}

	client := new(dns.Client)

	// Use a shared channel for the result to get the first successful IP record (A or AAAA).
	resultChan := make(chan net.IP, 2)
	errorChan := make(chan error, 2)
	var wg sync.WaitGroup

	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	wg.Add(len(queryTypes))

	for _, qType := range queryTypes {
		go func(qType uint16) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(fqdn, qType)

			queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
			defer cancel()

			resp, _, err := client.ExchangeContext(queryCtx, msg, upstreamServer)
			if err != nil {
				errorChan <- fmt.Errorf("upstream DNS query for %s [%s] failed: %w", name, dns.TypeToString[qType], err)
				return
			}

			if ip := r.parseResponse(resp, name); ip != nil {
				resultChan <- ip
				return
			}

			// If no direct records, check for a CNAME and resolve it.
			for _, answer := range resp.Answer {
				if cname, ok := answer.(*dns.CNAME); ok {
					log.Debug().Str("domain", name).Str("cname", cname.Target).Msg("DNS resolver: found CNAME, resolving recursively")
					_, ip, err := r.resolve(context.Background(), cname.Target, 0) // fresh context, depth 0
					if err == nil && ip != nil {
						resultChan <- ip
						return
					}
				}
			}
		}(qType)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	select {
	case ip := <-resultChan:
		if ip != nil {
			log.Debug().Str("domain", name).IPAddr("ip", ip).Msg("DNS resolver: answered from upstream")
			r.cache.Store(fqdn, dnsCacheEntry{ip: ip, expires: time.Now().Add(maxDNSCacheTTL)})
			return ip, nil
		}
	case err := <-errorChan:
		// Return the first error we receive.
		log.Warn().Str("domain", name).Err(err).Msg("DNS upstream lookup failed")
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return nil, fmt.Errorf("no A or AAAA records found for %s", name)
}

// parseResponse parses a DNS response, returning the first valid IP address found.
func (r *Resolver) parseResponse(resp *dns.Msg, name string) net.IP {
	for _, answer := range resp.Answer {
		switch v := answer.(type) {
		case *dns.A:
			return v.A
		case *dns.AAAA:
			return v.AAAA
		}
	}
	return nil
}
