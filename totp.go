package authenticator

import (
	"context"
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
			otp.TOTPSecretFromEnv(envTOTPSecret),
			newTOTPSecretGetter(namespace, account, c.logger),
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

// WithLogger sets the logger to use.
func WithLogger(logger ctxd.Logger) GenerateTOTPOption {
	return generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
		cfg.logger = logger
	})
}

// WithClock sets the clock to use.
func WithClock(clock clock.Clock) GenerateTOTPOption {
	return generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
		cfg.options = append(cfg.options, otp.WithClock(clock))
	})
}

type totpSecretGetter struct {
	logger ctxd.Logger

	namespace string
	account   string
	secret    otp.TOTPSecret
	fetchOnce sync.Once
}

func (s *totpSecretGetter) fetch(ctx context.Context) otp.TOTPSecret {
	if s.namespace == "" || s.account == "" {
		return otp.NoTOTPSecret
	}

	a, err := GetAccount(s.namespace, s.account)
	if err != nil {
		s.logger.Error(ctx, "could not get totp secret", "error", err, "namespace", s.namespace, "account", s.account)

		return otp.NoTOTPSecret
	}

	return a.TOTPSecret
}

// TOTPSecret returns the TOTP secret from the keyring.
func (s *totpSecretGetter) TOTPSecret(ctx context.Context) otp.TOTPSecret {
	s.fetchOnce.Do(func() {
		s.secret = s.fetch(ctx)
	})

	return s.secret
}

func newTOTPSecretGetter(namespace, account string, logger ctxd.Logger) otp.TOTPSecretGetter {
	return &totpSecretGetter{
		logger:    logger,
		namespace: namespace,
		account:   account,
	}
}
