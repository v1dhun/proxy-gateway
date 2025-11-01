// Package arp implements a cached reader for the Linux ARP table.
package arp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var cache = struct {
	sync.RWMutex
	table      map[string]string
	lastUpdate time.Time
}{table: make(map[string]string)}

const cacheTTL = 5 * time.Second
const filePath = "/proc/net/arp"

func GetMAC(ip net.IP) (net.HardwareAddr, error) {
	cache.RLock()
	if time.Since(cache.lastUpdate) < cacheTTL {
		macStr, found := cache.table[ip.String()]
		cache.RUnlock()
		if found {
			return net.ParseMAC(macStr)
		}
		return nil, errors.New("IP not found in cached ARP table")
	}
	cache.RUnlock()
	cache.Lock()
	defer cache.Unlock()
	if time.Since(cache.lastUpdate) < cacheTTL {
		if macStr, found := cache.table[ip.String()]; found {
			return net.ParseMAC(macStr)
		}
	}
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ARP table not available at %s (not Linux?)", filePath)
		}
		return nil, fmt.Errorf("could not open ARP table: %w", err)
	}
	defer file.Close()
	newTable := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[3] != "00:00:00:00:00:00" {
			newTable[fields[0]] = fields[3]
		}
	}
	cache.table = newTable
	cache.lastUpdate = time.Now()
	macStr, found := cache.table[ip.String()]
	if found {
		return net.ParseMAC(macStr)
	}
	return nil, errors.New("IP not found in refreshed ARP table")
}
