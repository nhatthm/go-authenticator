package authenticator

import (
	"context"
	"errors"
	"sync"

	"github.com/bool64/ctxd"
	"go.nhat.io/clock"
	"go.nhat.io/otp"
)

const envTOTPSecret = "AUTHENTICATOR_TOTP_SECRET"

type generateTOTPConfig struct {
	secretGetter otp.TOTPSecretGetter
	logger       ctxd.Logger
	options      []otp.TOTPGeneratorOption
}

// GenerateTOTP generates a TOTP code for the given account.
func GenerateTOTP(ctx context.Context, namespace, account string, opts ...GenerateTOTPOption) (otp.OTP, error) {
	c := &generateTOTPConfig{
		logger: ctxd.NoOpLogger{},
	}

	for _, opt := range opts {
		opt.applyGenerateTOTPOption(c)
	}

	if c.secretGetter == nil {
		c.secretGetter = otp.ChainTOTPSecretGetters(
			TOTPSecretFromEnv(),
			TOTPSecretFromAccount(namespace, account, WithLogger(c.logger)),
		)
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

// TOTPSecretFromEnv returns a TOTP secret from the environment.
func TOTPSecretFromEnv() otp.TOTPSecretProvider {
	return otp.TOTPSecretFromEnv(envTOTPSecret)
}

var _ otp.TOTPSecretProvider = (*TOTPSecretProvider)(nil)

// TOTPSecretProvider manages the TOTP secret.
type TOTPSecretProvider struct {
	logger ctxd.Logger

	namespace string
	account   string
	secret    otp.TOTPSecret

	mu        sync.Mutex
	fetchOnce sync.Once
}

func (s *TOTPSecretProvider) fetch(ctx context.Context) otp.TOTPSecret {
	ctx = ctxd.AddFields(ctx, "namespace", s.namespace, "account", s.account)

	if s.namespace == "" {
		s.logger.Debug(ctx, "failed to fetch totp secret due to missing namespace")

		return otp.NoTOTPSecret
	} else if s.account == "" {
		s.logger.Debug(ctx, "failed to fetch totp secret due to missing account")

		return otp.NoTOTPSecret
	}

	a, err := GetAccount(s.namespace, s.account)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			s.logger.Debug(ctx, "could not get totp secret", "error", err)
		} else {
			s.logger.Error(ctx, "could not get totp secret", "error", err)
		}

		return otp.NoTOTPSecret
	}

	return a.TOTPSecret
}

// TOTPSecret returns the TOTP secret from the keyring.
func (s *TOTPSecretProvider) TOTPSecret(ctx context.Context) otp.TOTPSecret {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fetchOnce.Do(func() {
		s.secret = s.fetch(ctx)
	})

	return s.secret
}

// SetTOTPSecret sets the TOTP secret to the keyring.
func (s *TOTPSecretProvider) SetTOTPSecret(_ context.Context, secret otp.TOTPSecret, issuer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := CreateNamespace(s.namespace, s.namespace)
	if err != nil && !errors.Is(err, ErrNamespaceExists) {
		return err
	}

	account, err := GetAccount(s.namespace, s.account)
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) {
			return err
		}

		account = Account{Name: s.account}
	}

	s.fetchOnce.Do(func() {})

	account.TOTPSecret = secret
	account.Issuer = issuer
	s.secret = secret

	return SetAccount(s.namespace, account)
}

// DeleteTOTPSecret deletes the TOTP secret from the keyring.
func (s *TOTPSecretProvider) DeleteTOTPSecret(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fetchOnce.Do(func() {})

	s.secret = otp.NoTOTPSecret

	return DeleteAccount(s.namespace, s.account)
}

// TOTPSecretFromAccount returns a TOTP secret getter for the given account.
func TOTPSecretFromAccount(namespace, account string, opts ...TOTPSecretProviderOption) *TOTPSecretProvider {
	p := &TOTPSecretProvider{
		logger:    ctxd.NoOpLogger{},
		namespace: namespace,
		account:   account,
	}

	for _, opt := range opts {
		opt.applyTOTPSecretProviderOption(p)
	}

	return p
}

// TOTPSecretProviderOption is an option to configure TOTPSecretProvider.
type TOTPSecretProviderOption interface {
	applyTOTPSecretProviderOption(p *TOTPSecretProvider)
}

type totpSecretProviderOptionFunc func(p *TOTPSecretProvider)

func (f totpSecretProviderOptionFunc) applyTOTPSecretProviderOption(p *TOTPSecretProvider) {
	f(p)
}
