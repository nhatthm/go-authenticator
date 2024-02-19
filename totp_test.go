package authenticator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.nhat.io/clock"
	"go.nhat.io/otp"
	"go.nhat.io/otp/keyring"
	mockotp "go.nhat.io/otp/mock"
	"go.nhat.io/secretstorage"
	mockss "go.nhat.io/secretstorage/mock"

	"go.nhat.io/authenticator"
)

func TestSetTOTPSecret(t *testing.T) {
	err := authenticator.SetTOTPSecret("test", t.Name(), "NBSWY3DP")
	require.NoError(t, err)

	key := fmt.Sprintf("%s/%s", "test", t.Name())
	s := secretstorage.NewKeyringStorage[otp.TOTPSecret]()

	t.Cleanup(func() {
		err := s.Delete("go.nhat.io/totp", key)
		require.NoError(t, err)
	})

	secret, err := s.Get("go.nhat.io/totp", key)
	require.NoError(t, err)

	require.Equal(t, "NBSWY3DP", string(secret))
}

func TestDeleteTOTPSecret_NotFound(t *testing.T) {
	t.Parallel()

	err := authenticator.DeleteTOTPSecret("test", t.Name())
	require.EqualError(t, err, `failed to delete data in keyring: secret not found in keyring`)
}

func TestDeleteTOTPSecret_Success(t *testing.T) {
	key := fmt.Sprintf("%s/%s", "test", t.Name())
	s := secretstorage.NewKeyringStorage[otp.TOTPSecret]()

	err := s.Set("go.nhat.io/totp", key, "NBSWY3DP")
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := s.Get("go.nhat.io/totp", key)
		require.ErrorIs(t, err, secretstorage.ErrNotFound)
	})

	err = authenticator.DeleteTOTPSecret("test", t.Name())
	require.NoError(t, err)
}

func TestGenerateTOTP_Failure_NoSecret(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", t.Name())
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromEnv(t *testing.T) {
	t.Setenv("AUTHENTICATOR_TOTP_SECRET", "NBSWY3DP")

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", "account",
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromEnv(t *testing.T) {
	t.Setenv("AUTHENTICATOR_TOTP_SECRET", "secret")

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", t.Name())
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromKeyring(t *testing.T) {
	t.Parallel()

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))
	k := keyring.TOTPSecretFromKeyring(fmt.Sprintf("%s/%s", "test", t.Name()))

	t.Cleanup(func() {
		err := k.DeleteTOTPSecret(context.Background())
		require.NoError(t, err)
	})

	err := k.SetTOTPSecret(context.Background(), "NBSWY3DP")
	require.NoError(t, err)

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", t.Name(),
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromKeyring(t *testing.T) {
	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Get", "go.nhat.io/totp", fmt.Sprintf("%s/%s", "test", t.Name())).
			Return(otp.NoTOTPSecret, assert.AnError)
	})

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", t.Name(),
		authenticator.WithClock(c),
	)
	require.EqualError(t, err, `could not generate otp: no totp secret`)
	require.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromTOTPSecret(t *testing.T) {
	t.Parallel()

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", "account",
		authenticator.WithTOTPSecret("NBSWY3DP"),
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromTOTPSecret(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", "account",
		authenticator.WithTOTPSecret("secret"),
	)
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}

func TestGenerateTOTP_Success_FromSecretGetter(t *testing.T) {
	t.Parallel()

	c := clock.Fix(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))
	s := mockotp.MockTOTPSecretGetter(func(g *mockotp.TOTPSecretGetter) {
		g.On("TOTPSecret", context.Background()).
			Return(otp.TOTPSecret("NBSWY3DP"))
	})(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", "account",
		authenticator.WithTOTPSecretGetter(s),
		authenticator.WithClock(c),
	)
	require.NoError(t, err)

	expected := otp.OTP("191882")

	require.Equal(t, expected, actual)
}

func TestGenerateTOTP_Failure_FromSecretGetter(t *testing.T) {
	t.Parallel()

	s := mockotp.MockTOTPSecretGetter(func(g *mockotp.TOTPSecretGetter) {
		g.On("TOTPSecret", context.Background()).
			Return(otp.TOTPSecret("secret"))
	})(t)

	actual, err := authenticator.GenerateTOTP(context.Background(), "test", "account",
		authenticator.WithTOTPSecretGetter(s),
	)
	require.EqualError(t, err, `could not generate otp: Decoding of secret as base32 failed.`)
	assert.Empty(t, actual)
}
