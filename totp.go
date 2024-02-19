package authenticator

import (
	"context"
	"fmt"

	"go.nhat.io/clock"
	"go.nhat.io/otp"
	"go.nhat.io/otp/keyring"
	"go.nhat.io/secretstorage"
)

const envTOTPSecret = "AUTHENTICATOR_TOTP_SECRET"

var totpSecretStorage secretstorage.Storage[otp.TOTPSecret] = secretstorage.NewKeyringStorage[otp.TOTPSecret]()

func formatTOTPSecretAccount(namespaceID, account string) string {
	return fmt.Sprintf("%s/%s", namespaceID, account)
}

func setTOTPSecret(namespaceID, account string, secret otp.TOTPSecret) error {
	return keyring.TOTPSecretFromKeyring(formatTOTPSecretAccount(namespaceID, account), keyring.WithStorage(totpSecretStorage)).
		SetTOTPSecret(context.Background(), secret)
}

func deleteTOTPSecret(namespaceID, account string) error {
	return keyring.TOTPSecretFromKeyring(formatTOTPSecretAccount(namespaceID, account), keyring.WithStorage(totpSecretStorage)).
		DeleteTOTPSecret(context.Background())
}

// SetTOTPSecret sets the TOTP secret for the account.
func SetTOTPSecret(namespaceID, account string, secret otp.TOTPSecret) error {
	configMu.Lock()
	defer configMu.Unlock()

	return setTOTPSecret(namespaceID, account, secret)
}

// DeleteTOTPSecret deletes the TOTP secret for the account.
func DeleteTOTPSecret(namespaceID, account string) error {
	configMu.Lock()
	defer configMu.Unlock()

	return deleteTOTPSecret(namespaceID, account)
}

// SetTOTPSecretStorage sets the TOTP secret storage.
func SetTOTPSecretStorage(s secretstorage.Storage[otp.TOTPSecret]) func() {
	configMu.Lock()
	defer configMu.Unlock()

	ts := totpSecretStorage
	totpSecretStorage = s

	return func() {
		totpSecretStorage = ts
	}
}

type generateTOTPConfig struct {
	secretGetter otp.TOTPSecretGetter
	options      []otp.TOTPGeneratorOption
}

// GenerateTOTP generates a TOTP code for the given account.
func GenerateTOTP(ctx context.Context, namespace, account string, opts ...GenerateTOTPOption) (otp.OTP, error) {
	c := &generateTOTPConfig{
		secretGetter: otp.ChainTOTPSecretGetters(
			otp.TOTPSecretFromEnv(envTOTPSecret),
			keyring.TOTPSecretFromKeyring(formatTOTPSecretAccount(namespace, account),
				keyring.WithStorage(totpSecretStorage),
			),
		),
	}

	for _, opt := range opts {
		opt.applyGenerateTOTPOption(c)
	}

	return otp.GenerateTOTP(ctx, c.secretGetter, c.options...) //nolint: wrapcheck
}

// GenerateTOTPOption is an option to configure generateTOTPConfig.
type GenerateTOTPOption interface {
	applyGenerateTOTPOption(cfg *generateTOTPConfig)
}

type generateTOTPOptionFunc func(cfg *generateTOTPConfig)

func (f generateTOTPOptionFunc) applyGenerateTOTPOption(cfg *generateTOTPConfig) {
	f(cfg)
}

// WithTOTPSecret sets the secret to use.
func WithTOTPSecret(s otp.TOTPSecret) GenerateTOTPOption {
	return generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
		cfg.secretGetter = otp.ChainTOTPSecretGetters(s, cfg.secretGetter)
	})
}

// WithTOTPSecretGetter sets the secret getter to use.
func WithTOTPSecretGetter(secretGetter otp.TOTPSecretGetter) GenerateTOTPOption {
	return generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
		cfg.secretGetter = secretGetter
	})
}

// WithClock sets the clock to use.
func WithClock(clock clock.Clock) GenerateTOTPOption {
	return generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
		cfg.options = append(cfg.options, otp.WithClock(clock))
	})
}
