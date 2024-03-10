package authenticator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bool64/ctxd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.nhat.io/clock"
	"go.nhat.io/otp"
	mockotp "go.nhat.io/otp/mock"
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
