package authenticator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bool64/ctxd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.nhat.io/clock"
	"go.nhat.io/otp"
	mockotp "go.nhat.io/otp/mock"
	"go.nhat.io/secretstorage"
	mockss "go.nhat.io/secretstorage/mock"

	"go.nhat.io/authenticator"
)

func TestGenerateTOTP_MissingNamespace(t *testing.T) {
	setAccountStorage(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), "", "john.doe@example.com")
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	require.Empty(t, actual)
}

func TestGenerateTOTP_MissingAccount(t *testing.T) {
	setAccountStorage(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "")
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	require.Empty(t, actual)
}

func TestGenerateTOTP_Failure_NoSecret(t *testing.T) {
	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com")
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromEnv(t *testing.T) {
	t.Setenv("AUTHENTICATOR_TOTP_SECRET", "NBSWY3DP")

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromEnv(t *testing.T) {
	t.Setenv("AUTHENTICATOR_TOTP_SECRET", "secret")

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com")
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromAccount(t *testing.T) {
	setConfigFile(t)

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	err = authenticator.SetAccount(t.Name(), authenticator.Account{Name: "john.doe@example.com", TOTPSecret: "NBSWY3DP"})
	require.NoError(t, err)

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithClock(c),
		authenticator.WithLogger(ctxd.NoOpLogger{}),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FailedToGetAccount(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, assert.AnError)
	})

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithClock(c),
	)
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	require.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromTOTPSecret(t *testing.T) {
	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithTOTPSecret("NBSWY3DP"),
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromTOTPSecret(t *testing.T) {
	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithTOTPSecret("secret"),
	)
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromSecretGetter(t *testing.T) {
	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))
	s := mockotp.MockTOTPSecretGetter(func(g *mockotp.TOTPSecretGetter) {
		g.On("TOTPSecret", context.Background()).
			Return(otp.TOTPSecret("NBSWY3DP"))
	})(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithTOTPSecretGetter(s),
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromSecretGetter(t *testing.T) {
	s := mockotp.MockTOTPSecretGetter(func(g *mockotp.TOTPSecretGetter) {
		g.On("TOTPSecret", context.Background()).
			Return(otp.TOTPSecret("secret"))
	})(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), t.Name(), "john.doe@example.com",
		authenticator.WithTOTPSecretGetter(s),
	)
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}

func TestTOTPSecretProvider_TOTPSecret_MissingNamespace(t *testing.T) {
	setAccountStorage(t)

	p := authenticator.TOTPSecretFromAccount("", "john.doe@example.com")

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.NoTOTPSecret, actual)
}

func TestTOTPSecretProvider_TOTPSecret_MissingAccount(t *testing.T) {
	setAccountStorage(t)

	p := authenticator.TOTPSecretFromAccount(t.Name(), "")

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.NoTOTPSecret, actual)
}

func TestTOTPSecretProvider_TOTPSecret_CouldNotGetAccount(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.NoTOTPSecret, actual)
}

func TestTOTPSecretProvider_TOTPSecret_AccountNotFound(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, secretstorage.ErrNotFound)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.NoTOTPSecret, actual)
}

func TestTOTPSecretProvider_TOTPSecret_Success(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{
				TOTPSecret: "secret",
			}, nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.TOTPSecret("secret"), actual)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_FailedToCreateNamespace(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to create namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_FailedToCreateNamespace: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_FailedToGetAccount(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to get account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_FailedToGetAccount: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountNotFound_FailedToSet(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"), mock.Anything).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to store account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountNotFound_FailedToSet: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountNotFound_Success(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).Once().
			Return(nil)

		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{Name: t.Name()}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(),
			authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}).
			Once().
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"),
			authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "secret",
				Issuer:     "issuer",
			}).
			Return(nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.NoError(t, err)

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.TOTPSecret("secret"), actual)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountExists_FailedToSet(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "old-secret",
				Issuer:     "old-issuer",
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"), mock.Anything).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to store account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountExists_FailedToSet: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceNotFound_AccountExists_Success(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).Once().
			Return(nil)

		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{Name: t.Name()}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(),
			authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}).
			Once().
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "old-secret",
				Issuer:     "old-issuer",
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"),
			authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "secret",
				Issuer:     "issuer",
			}).
			Return(nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.NoError(t, err)

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.TOTPSecret("secret"), actual)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_FailedToGetAccount(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))
	setNamespaceStorage(t)

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to get account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_FailedToGetAccount: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountNotFound_FailedToSet(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))
	setNamespaceStorage(t)

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"), mock.Anything).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to store account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountNotFound_FailedToSet: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountNotFound_Success(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Accounts: []string{"john.doe@example.com"},
			}, nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"),
			authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "secret",
				Issuer:     "issuer",
			}).
			Return(nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.NoError(t, err)

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.TOTPSecret("secret"), actual)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountExists_FailedToSet(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))
	setNamespaceStorage(t)

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "old-secret",
				Issuer:     "old-issuer",
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"), mock.Anything).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.EqualError(t, err, `failed to store account john.doe@example.com in namespace TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountExists_FailedToSet: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_SetTOTPSecret_NamespaceExists_AccountExists_Success(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Accounts: []string{"john.doe@example.com"},
			}, nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "old-secret",
				Issuer:     "old-issuer",
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com"),
			authenticator.Account{
				Name:       "john.doe@example.com",
				TOTPSecret: "secret",
				Issuer:     "issuer",
			}).
			Return(nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.SetTOTPSecret(context.Background(), "secret", "issuer")

	require.NoError(t, err)

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.TOTPSecret("secret"), actual)
}

func TestTOTPSecretProvider_DeleteTOTPSecret_Error(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(assert.AnError)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.DeleteTOTPSecret(context.Background())

	require.EqualError(t, err, `failed to delete account john.doe@example.com in namespace TestTOTPSecretProvider_DeleteTOTPSecret_Error: assert.AnError general error for testing`)
}

func TestTOTPSecretProvider_DeleteTOTPSecret_Success(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", fmt.Sprintf("%s/%s", t.Name(), "john.doe@example.com")).
			Return(nil)
	})

	p := authenticator.TOTPSecretFromAccount(t.Name(), "john.doe@example.com")

	err := p.DeleteTOTPSecret(context.Background())
	require.NoError(t, err)

	actual := p.TOTPSecret(context.Background())

	assert.Equal(t, otp.NoTOTPSecret, actual)
}
