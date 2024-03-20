package authenticator

import "github.com/bool64/ctxd"

// Option is a configuration option for services provided by this package.
type Option interface {
	GenerateTOTPOption
	TOTPSecretProviderOption
}

type option struct {
	GenerateTOTPOption
	TOTPSecretProviderOption
}

// WithLogger sets the logger to use.
func WithLogger(logger ctxd.Logger) Option {
	return option{
		GenerateTOTPOption: generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
			cfg.logger = logger
		}),
		TOTPSecretProviderOption: totpSecretProviderOptionFunc(func(p *TOTPSecretProvider) {
			p.logger = logger
		}),
	}
}
