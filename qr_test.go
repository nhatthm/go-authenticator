package authenticator_test

import (
	_ "image/jpeg"
	_ "image/png"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.nhat.io/authenticator"
)

func TestParseTOTPQRCode_Success(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/valid.png")
	require.NoError(t, err)

	assert.Equal(t, "NBSWY3DP", secret)
	assert.Equal(t, "john.doe@example.com", label)
	assert.Equal(t, "example.com", issuer)
}

func TestParseTOTPQRCode_FileNotFound(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/not_found.png")
	require.EqualError(t, err, `failed to qr code file: open resources/fixtures/not_found.png: no such file or directory`)

	assert.Empty(t, secret)
	assert.Empty(t, label)
	assert.Empty(t, issuer)
}

func TestParseTOTPQRCode_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/valid.bmp")
	require.EqualError(t, err, `failed to decode image: image: unknown format`) //nolint: dupword

	assert.Empty(t, secret)
	assert.Empty(t, label)
	assert.Empty(t, issuer)
}

func TestParseTOTPQRCode_NoQRCode(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_noqr.png")
	require.EqualError(t, err, `failed to decode qr code: NotFoundException: startSize = 0`)

	assert.Empty(t, secret)
	assert.Empty(t, label)
	assert.Empty(t, issuer)
}

func TestParseTOTPQRCode_WrongProtocol(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_link.png")
	require.EqualError(t, err, `invalid totpauth uri: https://example.com`)

	assert.Empty(t, secret)
	assert.Empty(t, label)
	assert.Empty(t, issuer)
}

func TestParseTOTPQRCode_InvalidTOTPURI(t *testing.T) {
	t.Parallel()

	secret, label, issuer, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_totpauth_uri.png")
	require.EqualError(t, err, `failed to parse otpauth uri: parse "otpauth://totp/\tjohn.doe%40example.com?secret=NBSWY3DP&issuer=example.com": net/url: invalid control character in URL`)

	assert.Empty(t, secret)
	assert.Empty(t, label)
	assert.Empty(t, issuer)
}
