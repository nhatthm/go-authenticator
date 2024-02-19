package authenticator

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/pelletier/go-toml/v2"
	"go.nhat.io/secretstorage"
	"go.uber.org/multierr"
)

var (
	// ErrNamespaceExists indicates that the namespace already exists.
	ErrNamespaceExists = errors.New("namespace already exists")
	// ErrNamespaceNotFound indicates that the namespace was not found.
	ErrNamespaceNotFound = errors.New("namespace not found")
)

const (
	serviceName = "go.nhat.io/authenticator"

	configFile = `.authenticator.toml`

	envConfigFile = "AUTHENTICATOR_CONFIG"
)

var namespaceStorage secretstorage.Storage[Namespace] = secretstorage.NewKeyringStorage[Namespace]()

var configMu sync.RWMutex

type config struct {
	Namespaces []string `json:"namespaces" toml:"namespaces" yaml:"namespaces"`
}

// Namespace represents a namespace.
type Namespace struct {
	Name     string   `json:"name" toml:"name" yaml:"name"`
	Accounts []string `json:"accounts" toml:"accounts" yaml:"accounts"`
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (c *Namespace) UnmarshalText(text []byte) error {
	type t Namespace

	var ct t

	if err := toml.Unmarshal(text, &ct); err != nil {
		return fmt.Errorf("failed to unmarshal namespace: %w", err)
	}

	*c = Namespace(ct)

	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (c Namespace) MarshalText() (text []byte, err error) {
	type t Namespace

	data, err := toml.Marshal(t(c))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal namespace: %w", err)
	}

	return data, nil
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

// GetAllNamespaceIDs returns all namespace ids.
func GetAllNamespaceIDs() ([]string, error) {
	configMu.RLock()
	defer configMu.RUnlock()

	cfg, err := loadConfigFile()
	if err != nil {
		return nil, err
	}

	return cfg.Namespaces, nil
}

func getNamespace(id string) (Namespace, error) {
	n, err := namespaceStorage.Get(serviceName, id)
	if err != nil {
		if errors.Is(err, secretstorage.ErrNotFound) {
			return Namespace{}, fmt.Errorf("failed to get namespace %s: %w", id, ErrNamespaceNotFound)
		}

		return Namespace{}, fmt.Errorf("failed to get namespace %s: %w", id, err)
	}

	return n, nil
}

// GetNamespace returns the namespace.
func GetNamespace(id string) (Namespace, error) {
	configMu.RLock()
	defer configMu.RUnlock()

	return getNamespace(id)
}

// CreateNamespace creates a new namespace.
func CreateNamespace(id, name string) error {
	configMu.Lock()
	defer configMu.Unlock()

	cfg, err := loadConfigFile()
	if err != nil {
		return err
	}

	if slices.Contains(cfg.Namespaces, id) {
		return fmt.Errorf("%w: %s", ErrNamespaceExists, id)
	}

	if _, err := getNamespace(id); err == nil {
		return fmt.Errorf("%w in storage: %s", ErrNamespaceExists, id)
	}

	err = updateNamespace(id, Namespace{Name: name})
	if err != nil {
		return fmt.Errorf("failed to create namespace %s: %w", id, errors.Unwrap(err))
	}

	cfg.Namespaces = append(cfg.Namespaces, id)

	sort.Strings(cfg.Namespaces)

	err = saveConfigFile(cfg)
	if err != nil {
		// Rollback.
		if dErr := namespaceStorage.Delete(serviceName, id); dErr != nil {
			err = multierr.Combine(err, fmt.Errorf("failed to delete namespace: %w", dErr))
		}
	}

	return err
}

func updateNamespace(id string, n Namespace) error {
	err := namespaceStorage.Set(serviceName, id, n)
	if err != nil {
		return fmt.Errorf("failed to update namespace %s: %w", id, err)
	}

	return nil
}

// UpdateNamespace updates the namespace.
func UpdateNamespace(id string, n Namespace) error {
	configMu.Lock()
	defer configMu.Unlock()

	return updateNamespace(id, n)
}

func deleteNamespace(id string) error {
	cfg, err := loadConfigFile()
	if err != nil {
		return err
	}

	if slices.Contains(cfg.Namespaces, id) {
		cfg.Namespaces = slices.DeleteFunc(cfg.Namespaces, func(s string) bool {
			return s == id
		})

		if err := saveConfigFile(cfg); err != nil {
			return fmt.Errorf("failed to delete namespace: %w", err)
		}
	}

	n, err := getNamespace(id)
	if err != nil {
		if errors.Is(err, ErrNamespaceNotFound) {
			return nil
		}

		return fmt.Errorf("failed to get namespace for deletion: %w", errors.Unwrap(err))
	}

	err = namespaceStorage.Delete(serviceName, id)
	if err != nil {
		return fmt.Errorf("failed to delete namespace: %w", err)
	}

	for _, account := range n.Accounts {
		if err := deleteTOTPSecret(id, account); err != nil && !errors.Is(err, secretstorage.ErrNotFound) {
			return fmt.Errorf("failed to delete TOTP secret of %s: %w", account, err)
		}
	}

	return nil
}

// DeleteNamespace deletes a namespace.
func DeleteNamespace(id string) error {
	configMu.Lock()
	defer configMu.Unlock()

	return deleteNamespace(id)
}

// AddAccountToNamespace adds an account to a namespace.
func AddAccountToNamespace(namespaceID, account string) error {
	configMu.Lock()
	defer configMu.Unlock()

	n, err := getNamespace(namespaceID)
	if err != nil {
		return err
	}

	if slices.Contains(n.Accounts, account) {
		return nil
	}

	n.Accounts = append(n.Accounts, account)

	slices.Sort(n.Accounts)

	return updateNamespace(namespaceID, n)
}

// DeleteAccountInNamespace deletes an account from a namespace.
func DeleteAccountInNamespace(namespaceID, account string) error {
	configMu.Lock()
	defer configMu.Unlock()

	n, err := getNamespace(namespaceID)
	if err != nil {
		return err
	}

	if slices.Contains(n.Accounts, account) {
		n.Accounts = slices.DeleteFunc(n.Accounts, func(s string) bool {
			return s == account
		})

		if err := updateNamespace(namespaceID, n); err != nil {
			return fmt.Errorf("failed to delete account %s in namespace: %w", account, errors.Unwrap(err))
		}
	}

	if err := deleteTOTPSecret(namespaceID, account); err != nil && !errors.Is(err, secretstorage.ErrNotFound) {
		return fmt.Errorf("failed to delete TOTP secret of %s: %w", account, err)
	}

	return nil
}

// SetNamespaceStorage sets the namespace storage.
func SetNamespaceStorage(s secretstorage.Storage[Namespace]) func() {
	configMu.Lock()
	defer configMu.Unlock()

	ns := namespaceStorage
	namespaceStorage = s

	return func() {
		namespaceStorage = ns
	}
}
