package authenticator

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"go.nhat.io/secretstorage"
	"go.uber.org/multierr"
)

var (
	// ErrNamespaceExists indicates that the namespace already exists.
	ErrNamespaceExists = errors.New("namespace already exists")
	// ErrNamespaceNotFound indicates that the namespace was not found.
	ErrNamespaceNotFound = errors.New("namespace not found")
)

var namespaceStorage secretstorage.Storage[Namespace] = secretstorage.NewKeyringStorage[Namespace]()

// Namespace represents a namespace.
type Namespace struct {
	Name     string   `json:"name" toml:"name" yaml:"name"`
	Accounts []string `json:"accounts" toml:"accounts" yaml:"accounts"`
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (c *Namespace) UnmarshalText(text []byte) error {
	type namespace Namespace

	var ct namespace

	if err := json.Unmarshal(text, &ct); err != nil {
		return fmt.Errorf("failed to unmarshal namespace: %w", err)
	}

	*c = Namespace(ct)

	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (c Namespace) MarshalText() (text []byte, err error) {
	type namespace Namespace

	data, err := json.Marshal(namespace(c))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal namespace: %w", err)
	}

	return data, nil
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
		if err := deleteAccount(id, account); err != nil && !errors.Is(err, secretstorage.ErrNotFound) {
			return fmt.Errorf("failed to delete account %s: %w", account, errors.Unwrap(err))
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
