// Package policy implements the advanced, conditional access control engine.
package policy

import (
	"net"
	"proxy-gateway/internal/arp"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/manager"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/rs/zerolog/log"
)

// Engine is the policy evaluation engine. It reads from the live config.
type Engine struct {
	cm *manager.ConfigManager
}

// NewEngine creates a new policy engine.
func NewEngine(cm *manager.ConfigManager) *Engine {
	return &Engine{cm: cm}
}

// Evaluate checks a request against the current, live policies.
// It returns the action to take (allow or deny) and the name of the policy that matched.
// If no policy matches, it returns a "default_deny" action.
func (pe *Engine) Evaluate(proxyName string, clientIP net.IP, clientHost []string, destHost string, destIP net.IP, destPort int) (config.PolicyAction, string) {
	cfg := pe.cm.Get()
	var currentProxy config.ProxyConfig
	found := false
	for _, p := range cfg.Proxies {
		if p.Name == proxyName {
			currentProxy = p
			found = true
			break
		}
	}

	if !found {
		return config.DenyAction, "proxy_not_found"
	}

	for _, p := range currentProxy.Policies {
		// Skip disabled policies
		if p.Disabled {
			continue
		}
		if matches(p, cfg.Groups, clientIP, clientHost, destHost, destIP, destPort) {
			return p.Action, p.Name
		}
	}

	return config.DenyAction, "default_deny"
}

// matches performs the logic check for a single policy rule.
// It evaluates all conditions in the policy and returns true if the request matches.
func matches(p config.Policy, allGroups []config.Group, clientIP net.IP, clientHost []string, destHost string, destIP net.IP, destPort int) bool {
	now := time.Now().UTC()
	if len(p.Conditions.DaysOfWeek) > 0 {
		dayMatch := false
		for _, dayStr := range p.Conditions.DaysOfWeek {
			if strings.EqualFold(string(dayStr), now.Weekday().String()) {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}

	if p.Conditions.TimeOfDay != "" {
		parts := strings.Split(p.Conditions.TimeOfDay, "-")
		if len(parts) == 2 {
			startTime, err1 := time.Parse("15:04", parts[0])
			endTime, err2 := time.Parse("15:04", parts[1])
			if err1 == nil && err2 == nil {
				currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)
				if currentTime.Before(startTime) || currentTime.After(endTime) {
					return false
				}
			}
		}
	}

	if len(p.Conditions.ClientGroups) > 0 {
		groupMatch := false
		for _, groupName := range p.Conditions.ClientGroups {
			for _, group := range allGroups {
				if group.Name == groupName {
					// Check IPs in the group
					for _, cidrStr := range group.ClientIPs {
						_, ipNet, err := net.ParseCIDR(cidrStr)
						if err == nil && ipNet.Contains(clientIP) {
							groupMatch = true
							break
						}
					}
					if groupMatch {
						break
					}

					// Check hosts in the group
					for _, hostPattern := range group.ClientHosts {
						g, err := glob.Compile(hostPattern)
						if err == nil {
							for _, h := range clientHost {
								if g.Match(h) {
									groupMatch = true
									break
								}
							}
						}
						if groupMatch {
							break
						}
					}
				}
				if groupMatch {
					break
				}
			}
			if groupMatch {
				break
			}
		}
		if !groupMatch {
			return false
		}
	}

	if len(p.Conditions.ClientMACs) > 0 {
		clientMAC, err := arp.GetMAC(clientIP)
		if err != nil {
			log.Debug().Err(err).IPAddr("client_ip", clientIP).Msg("Could not get MAC for client; failing MAC policy check")
			return false
		}
		macMatch := false
		for _, macStr := range p.Conditions.ClientMACs {
			policyMAC, err := net.ParseMAC(macStr)
			if err == nil && clientMAC.String() == policyMAC.String() {
				macMatch = true
				break
			}
		}
		if !macMatch {
			return false
		}
	}

	if len(p.Conditions.DestHosts) > 0 {
		hostMatch := false
		for _, hostPattern := range p.Conditions.DestHosts {
			g, err := glob.Compile(hostPattern)
			if err == nil && g.Match(destHost) {
				hostMatch = true
				break
			}
		}
		if !hostMatch {
			return false
		}
	}

	if len(p.Conditions.DestIPs) > 0 {
		if destIP == nil {
			return false
		}
		ipMatch := false
		for _, cidrStr := range p.Conditions.DestIPs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err == nil && ipNet.Contains(destIP) {
				ipMatch = true
				break
			}
		}
		if !ipMatch {
			return false
		}
	}

	if len(p.Conditions.DestPorts) > 0 {
		portMatch := false
		for _, port := range p.Conditions.DestPorts {
			if port == destPort {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	return true
}
