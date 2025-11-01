// Package proxy defines the core interface for all proxy services.
package proxy

import (
	"context"
	"net"
)

// ClientInfo holds information about a client connection.
type ClientInfo struct {
	IP       net.IP
	Hostname string
}

// Proxy is the interface for all proxy services.
type Proxy interface {
	Name() string
	Start(ctx context.Context) error
}
