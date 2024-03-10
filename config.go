package authenticator

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

const (
	serviceName = "go.nhat.io/authenticator"

	configFile = `.authenticator.toml`

	envConfigFile = "AUTHENTICATOR_CONFIG"
)

var configMu sync.RWMutex

type config struct {
	Namespaces []string `json:"namespaces" toml:"namespaces" yaml:"namespaces"`
}

func getConfigFile() string {
	userConfigFile := os.Getenv(envConfigFile)
	if userConfigFile == "" {
		dirname, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Errorf("failed to get user home directory: %w", err))
		}

		userConfigFile = filepath.Join(dirname, configFile)
	}

	return userConfigFile
}

func loadConfigFile() (config, error) {
	f, err := os.Open(getConfigFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config{}, nil
		}

		return config{}, fmt.Errorf("failed to open config file: %w", err)
	}

	defer f.Close() //nolint: errcheck

	var cfg config

	if err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("failed to decode config file: %w", err)
	}

	return cfg, nil
}

func saveConfigFile(cfg config) error {
	f, err := os.OpenFile(getConfigFile(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}

	defer f.Close() //nolint: errcheck

	buf := bufio.NewWriter(f)

	if err := toml.NewEncoder(buf).Encode(cfg); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	buf.Flush() //nolint: errcheck,gosec

	return nil
}
