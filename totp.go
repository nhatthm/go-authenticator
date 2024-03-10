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
func TOTPSecretFromEnv() otp.TOTPSecretGetter {
	return otp.TOTPSecretFromEnv(envTOTPSecret)
}

// TOTPSecretGetter gets the TOTP secret.
type TOTPSecretGetter struct {
	logger ctxd.Logger

	namespace string
	account   string
	secret    otp.TOTPSecret
	fetchOnce sync.Once
}

func (s *TOTPSecretGetter) fetch(ctx context.Context) otp.TOTPSecret {
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
		s.logger.Error(ctx, "could not get totp secret", "error", err)

		return otp.NoTOTPSecret
	}

	return a.TOTPSecret
}

// TOTPSecret returns the TOTP secret from the keyring.
func (s *TOTPSecretGetter) TOTPSecret(ctx context.Context) otp.TOTPSecret {
	s.fetchOnce.Do(func() {
		s.secret = s.fetch(ctx)
	})

	return s.secret
}

// TOTPSecretFromAccount returns a TOTP secret getter for the given account.
func TOTPSecretFromAccount(namespace, account string, opts ...TOTPSecretGetterOption) otp.TOTPSecretGetter {
	g := &TOTPSecretGetter{
		logger:    ctxd.NoOpLogger{},
		namespace: namespace,
		account:   account,
	}

	for _, opt := range opts {
		opt.applyTOTPSecretGetterOption(g)
	}

	return g
}

// TOTPSecretGetterOption is an option to configure TOTPSecretGetter.
type TOTPSecretGetterOption interface {
	applyTOTPSecretGetterOption(g *TOTPSecretGetter)
}

type totpSecretGetterOptionFunc func(g *TOTPSecretGetter)

func (f totpSecretGetterOptionFunc) applyTOTPSecretGetterOption(g *TOTPSecretGetter) {
	f(g)
}
