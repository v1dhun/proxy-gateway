// Package proxy contains the mDNS reflector implementation.
package proxy

import (
	"context"
	"fmt"
	"net"
	"proxy-gateway/internal/config"
	"sync"

	"github.com/rs/zerolog/log"
)

const mdnsGroup = "224.0.0.251:5353"

// MDNSReflector implements the Proxy interface for reflecting mDNS traffic between interfaces.
type MDNSReflector struct {
	name       string
	interfaces []string
}

// NewMDNSReflector creates a new MDNSReflector instance.
func NewMDNSReflector(cfg config.ProxyConfig) *MDNSReflector {
	return &MDNSReflector{
		name:       cfg.Name,
		interfaces: cfg.Interfaces,
	}
}

// Name returns the name of the proxy.
func (m *MDNSReflector) Name() string { return m.name }

// Start starts the mDNS reflector.
func (m *MDNSReflector) Start(ctx context.Context) error {
	if len(m.interfaces) < 2 {
		return fmt.Errorf("mDNS reflector requires at least two interfaces")
	}
	log.Info().Str("proxy_name", m.name).Strs("interfaces", m.interfaces).Msg("Starting mDNS reflector. NOTE: This may require root privileges.")
	addr, err := net.ResolveUDPAddr("udp", mdnsGroup)
	if err != nil {
		return fmt.Errorf("failed to resolve mDNS group address: %w", err)
	}
	var conns []*net.UDPConn
	for _, ifaceName := range m.interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("failed to find interface '%s': %w", ifaceName, err)
		}
		conn, err := net.ListenMulticastUDP("udp", iface, addr)
		if err != nil {
			return fmt.Errorf("failed to listen on multicast group on '%s' (check permissions): %w", ifaceName, err)
		}
		conns = append(conns, conn)
	}
	var wg sync.WaitGroup
	for i, conn := range conns {
		otherConns := make([]*net.UDPConn, 0, len(conns)-1)
		for j, other := range conns {
			if i != j {
				otherConns = append(otherConns, other)
			}
		}
		wg.Add(1)
		go m.reflect(conn, otherConns, &wg)
	}
	<-ctx.Done()
	log.Warn().Str("proxy_name", m.name).Msg("Stopping mDNS reflector")
	for _, conn := range conns {
		conn.Close()
	}
	wg.Wait()
	return nil
}

// reflect reads mDNS packets from a reader connection and writes them to a slice of writer connections.
func (m *MDNSReflector) reflect(reader *net.UDPConn, writers []*net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	addr, _ := net.ResolveUDPAddr("udp", mdnsGroup)
	buf := make([]byte, 4096)
	for {
		n, _, err := reader.ReadFromUDP(buf)
		if err != nil {
			return
		}
		for _, writer := range writers {
			if _, err := writer.WriteToUDP(buf[:n], addr); err != nil {
				log.Debug().Err(err).Str("proxy_name", m.name).Msg("mDNS write error")
			}
		}
	}
}
