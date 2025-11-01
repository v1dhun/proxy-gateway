// Package proxy contains the stateful UDP proxy implementation.
package proxy

import (
	"context"
	"fmt"
	"net"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/policy"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// UDPConnPool is a pool of UDP connections to the forward address.
// This is used to avoid creating a new connection for each incoming packet.
type UDPConnPool struct {
	pool *sync.Pool
}

// NewUDPConnPool creates a new UDP connection pool.
func NewUDPConnPool(forwardAddr *net.UDPAddr) *UDPConnPool {
	return &UDPConnPool{
		pool: &sync.Pool{
			New: func() interface{} {
				newConn, dialErr := net.DialUDP("udp", nil, forwardAddr)
				if dialErr != nil {
					log.Error().Err(dialErr).Msg("Failed to dial UDP destination")
					return nil
				}
				return newConn
			},
		},
	}
}

// Get gets a UDP connection from the pool.
func (p *UDPConnPool) Get() *net.UDPConn {
	conn := p.pool.Get()
	if conn == nil {
		return nil
	}
	return conn.(*net.UDPConn)
}

// Put returns a UDP connection to the pool.
func (p *UDPConnPool) Put(conn *net.UDPConn) {
	p.pool.Put(conn)
}

// UDPProxy implements the Proxy interface for stateful UDP forwarding.
type UDPProxy struct {
	name             string
	listenAddress    string
	forwardToAddress string
	pe               *policy.Engine
	connPool         *UDPConnPool
}

// NewUDPProxy creates and configures a new UDPProxy instance.
func NewUDPProxy(cfg config.ProxyConfig, pe *policy.Engine) *UDPProxy {
	forwardAddr, err := net.ResolveUDPAddr("udp", cfg.ForwardToAddress)
	if err != nil {
		// This should have been caught by validation, but fatal here just in case.
		log.Fatal().Err(err).Str("proxy_name", cfg.Name).Msg("Invalid forward_to_address")
	}
	return &UDPProxy{
		name:             cfg.Name,
		listenAddress:    cfg.ListenAddress,
		forwardToAddress: cfg.ForwardToAddress,
		pe:               pe,
		connPool:         NewUDPConnPool(forwardAddr),
	}
}

// Name returns the name of the proxy.
func (p *UDPProxy) Name() string { return p.name }

// Start starts the UDP proxy server.
func (p *UDPProxy) Start(ctx context.Context) error {
	listenAddr, err := net.ResolveUDPAddr("udp", p.listenAddress)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer conn.Close()
	forwardAddr, err := net.ResolveUDPAddr("udp", p.forwardToAddress)
	if err != nil {
		return fmt.Errorf("invalid forward_to_address: %w", err)
	}
	log.Info().Str("proxy_name", p.name).Str("address", p.listenAddress).Msg("Starting Stateful UDP proxy")
	go func() {
		<-ctx.Done()
		log.Warn().Str("proxy_name", p.name).Msg("Stopping UDP proxy, closing active connections")
		conn.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
				return nil // Graceful shutdown
			}
			return fmt.Errorf("UDP read error: %w", err)
		}
		if p.pe != nil {
			clientHostnames, err := net.LookupAddr(clientAddr.IP.String())
			if err != nil {
				log.Debug().Err(err).Str("proxy_name", p.name).Str("client_ip", clientAddr.IP.String()).Msg("Could not perform reverse DNS lookup for client")
			}

			action, ruleName := p.pe.Evaluate(p.name, clientAddr.IP, clientHostnames, "", forwardAddr.IP, forwardAddr.Port)
			if action == config.DenyAction {
				log.Debug().Str("proxy_name", p.name).Str("client_ip", clientAddr.IP.String()).Str("rule_name", ruleName).Msg("UDP packet denied by policy")
				continue
			}
		}
		remoteConn := p.connPool.Get()
		if remoteConn == nil {
			continue
		}
		if _, writeErr := remoteConn.Write(buf[:n]); writeErr != nil {
			log.Warn().Err(writeErr).Str("proxy_name", p.name).Msg("UDP write error to destination")
		}
		go p.handleUDPReply(conn, clientAddr, remoteConn)
	}
}

// handleUDPReply handles the reply from the forward address and sends it back to the client.
func (p *UDPProxy) handleUDPReply(listener *net.UDPConn, client *net.UDPAddr, remote *net.UDPConn) {
	defer p.connPool.Put(remote)
	replyBuf := make([]byte, 4096)
	for {

		if err := remote.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			log.Printf("failed to set read deadline: %v", err)
		}

		m, _, readErr := remote.ReadFromUDP(replyBuf)
		if readErr != nil {
			// This is expected when the connection times out
			return
		}
		if _, writeErr := listener.WriteToUDP(replyBuf[:m], client); writeErr != nil {
			// This can happen if the client has disconnected
			return
		}
	}
}
