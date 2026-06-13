package assert

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ConfigFile represents a .certs.yaml config file.
type ConfigFile struct {
	Profile    string   `yaml:"profile,omitempty"`
	Assertions []string `yaml:"assertions,omitempty"`
	Targets    []string `yaml:"targets,omitempty"`
}

// LoadConfig reads and parses a .certs.yaml config file.
func LoadConfig(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// FindConfig looks for a config file at explicit path, .certs.yaml,
// or ~/.config/certs/config.yaml. Returns the path and config, or
// empty string and nil if not found.
func FindConfig(explicit string) (string, *ConfigFile) {
	if explicit != "" {
		cfg, err := LoadConfig(explicit)
		if err != nil {
			return explicit, nil
		}
		return explicit, cfg
	}

	// Check current directory
	if cfg, err := LoadConfig(".certs.yaml"); err == nil {
		return ".certs.yaml", cfg
	}

	// Check ~/.config/certs/config.yaml
	home, err := os.UserHomeDir()
	if err == nil {
		globalPath := home + "/.config/certs/config.yaml"
		if cfg, err := LoadConfig(globalPath); err == nil {
			return globalPath, cfg
		}
	}

	return "", nil
}
