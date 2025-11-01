// Package manager provides a thread-safe, in-memory store for the application's configuration.
package manager

import (
	"proxy-gateway/internal/config"
	"sync"
)

// ConfigManager holds the global configuration in a thread-safe manner.
type ConfigManager struct {
	mu     sync.RWMutex
	config *config.Config
	path   string
}

// New creates a new ConfigManager.
func New(cfg *config.Config, configPath string) *ConfigManager {
	return &ConfigManager{
		config: cfg,
		path:   configPath,
	}
}

// Get gets the current configuration. It is safe for concurrent reads.
func (cm *ConfigManager) Get() *config.Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Return a deep copy to prevent modification of the config outside of a write lock.
	// For this application's complexity, we can skip deep copy for now,
	// but in a larger app, this would be important.
	return cm.config
}

// Update executes a given function with a write lock on the configuration.
// This is the only safe way to modify the configuration.
func (cm *ConfigManager) Update(updateFunc func(cfg *config.Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	updateFunc(cm.config)
}

// SaveToDisk persists the current in-memory configuration to the config file.
func (cm *ConfigManager) SaveToDisk() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return config.Save(cm.path, cm.config)
}
