package authenticator

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"go.nhat.io/otp"
	"go.nhat.io/secretstorage"
)

// ErrAccountNotFound indicates that the account was not found.
var ErrAccountNotFound = errors.New("account not found")

var accountStorage secretstorage.Storage[Account] = secretstorage.NewKeyringStorage[Account]()

// Account represents an account.
type Account struct {
	Name       string         `json:"name" toml:"name" yaml:"name"`
	TOTPSecret otp.TOTPSecret `json:"totp_secret" toml:"totp_secret" yaml:"totp_secret"`
	Issuer     string         `json:"issuer" toml:"issuer" yaml:"issuer"`
	Metadata   map[string]any `json:"metadata" toml:"metadata" yaml:"metadata"`
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (a *Account) UnmarshalText(text []byte) error {
	type account Account

	var ct account

	if err := json.Unmarshal(text, &ct); err != nil {
		return fmt.Errorf("failed to unmarshal account: %w", err)
	}

	*a = Account(ct)

	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (a Account) MarshalText() (text []byte, err error) {
	type account Account

	data, err := json.Marshal(account(a))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal account: %w", err)
	}

	return data, nil
}

// GetAccount returns the account.
func GetAccount(namespace, account string) (Account, error) {
	configMu.RLock()
	defer configMu.RUnlock()

	return getAccount(namespace, account)
}

func getAccount(namespace string, account string) (Account, error) {
	a, err := accountStorage.Get(serviceName, formatAccount(namespace, account))
	if err != nil {
		if errors.Is(err, secretstorage.ErrNotFound) {
			return Account{}, fmt.Errorf("failed to get account %s in namespace %s: %w", account, namespace, ErrAccountNotFound)
		}

		return Account{}, fmt.Errorf("failed to get account %s in namespace %s: %w", account, namespace, err)
	}

	return a, nil
}

// SetAccount persists the account.
func SetAccount(namespace string, account Account) error {
	configMu.Lock()
	defer configMu.Unlock()

	if err := setAccount(namespace, account); err != nil {
		return err
	}

	n, err := getNamespace(namespace)
	if err != nil {
		return fmt.Errorf("failed to get namespace %s for creating account %s: %w", namespace, account.Name, errors.Unwrap(err))
	}

	if slices.Contains(n.Accounts, account.Name) {
		return nil
	}

	n.Accounts = append(n.Accounts, account.Name)

	slices.Sort(n.Accounts)

	return updateNamespace(namespace, n)
}

func setAccount(namespace string, account Account) error {
	if err := accountStorage.Set(serviceName, formatAccount(namespace, account.Name), account); err != nil {
		return fmt.Errorf("failed to store account %s in namespace %s: %w", account.Name, namespace, err)
	}

	return nil
}

// DeleteAccount deletes the account and removes it from the namespace.
func DeleteAccount(namespace string, account string) error {
	configMu.Lock()
	defer configMu.Unlock()

	n, err := getNamespace(namespace)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		return fmt.Errorf("failed to get namespace %s for deleting account %s: %w", namespace, account, errors.Unwrap(err))
	}

	if slices.Contains(n.Accounts, account) {
		n.Accounts = slices.DeleteFunc(n.Accounts, func(s string) bool {
			return s == account
		})

		if err := updateNamespace(namespace, n); err != nil {
			return fmt.Errorf("failed to remove account %s from namespace %s: %w", account, namespace, errors.Unwrap(err))
		}
	}

	if err := deleteAccount(namespace, account); err != nil && !errors.Is(err, secretstorage.ErrNotFound) {
		return err
	}

	return nil
}

func deleteAccount(namespace string, account string) error {
	if err := accountStorage.Delete(serviceName, formatAccount(namespace, account)); err != nil {
		return fmt.Errorf("failed to delete account %s in namespace %s: %w", account, namespace, err)
	}

	return nil
}

// SetAccountStorage sets the account storage.
func SetAccountStorage(s secretstorage.Storage[Account]) func() {
	configMu.Lock()
	defer configMu.Unlock()

	ns := accountStorage
	accountStorage = s

	return func() {
		accountStorage = ns
	}
}

func formatAccount(namespace, account string) string {
	return fmt.Sprintf("%s/%s", namespace, account)
}
