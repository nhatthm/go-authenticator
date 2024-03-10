package authenticator

import "github.com/bool64/ctxd"

// Option is a configuration option for services provided by this package.
type Option interface {
	GenerateTOTPOption
	TOTPSecretGetterOption
}

type option struct {
	GenerateTOTPOption
	TOTPSecretGetterOption
}

// WithLogger sets the logger to use.
func WithLogger(logger ctxd.Logger) Option {
	return option{
		GenerateTOTPOption: generateTOTPOptionFunc(func(cfg *generateTOTPConfig) {
			cfg.logger = logger
		}),
		TOTPSecretGetterOption: totpSecretGetterOptionFunc(func(g *TOTPSecretGetter) {
			g.logger = logger
		}),
	}
}
