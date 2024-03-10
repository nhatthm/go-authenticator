package authenticator_test

import (
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.nhat.io/authenticator"
)

func TestParseTOTPQRCode_Success(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/valid.png")
	require.NoError(t, err)

	expected := authenticator.Account{
		Name:       "john.doe@example.com",
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	}

	assert.Equal(t, expected, actual)
}

func TestParseTOTPQRCode_FileNotFound(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/not_found.png")
	require.ErrorContains(t, err, `failed to qr code file`)
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, actual)
}

func TestParseTOTPQRCode_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/valid.bmp")
	require.EqualError(t, err, `failed to decode image: image: unknown format`) //nolint: dupword
	assert.Empty(t, actual)
}

func TestParseTOTPQRCode_NoQRCode(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_noqr.png")
	require.EqualError(t, err, `failed to decode qr code: NotFoundException: startSize = 0`)
	assert.Empty(t, actual)
}

func TestParseTOTPQRCode_WrongProtocol(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_link.png")
	require.EqualError(t, err, `invalid totpauth uri: https://example.com`)
	assert.Empty(t, actual)
}

func TestParseTOTPQRCode_InvalidTOTPURI(t *testing.T) {
	t.Parallel()

	actual, err := authenticator.ParseTOTPQRCode("resources/fixtures/invalid_totpauth_uri.png")
	require.EqualError(t, err, `failed to parse otpauth uri: parse "otpauth://totp/\tjohn.doe%40example.com?secret=NBSWY3DP&issuer=example.com": net/url: invalid control character in URL`)
	assert.Empty(t, actual)
}

func TestGenerateTOTPQRCode_Success_PNG(t *testing.T) {
	t.Parallel()

	actualFile := filepath.Join(t.TempDir(), "qr.png")

	account := authenticator.Account{
		Name:       "john.doe@example.com",
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	}

	err := authenticator.GenerateTOTPQRCode(actualFile, account, 200, 200, map[gozxing.EncodeHintType]any{
		gozxing.EncodeHintType_MARGIN: 1,
	})
	require.NoError(t, err)

	actualFileContent, err := os.ReadFile(actualFile) //nolint: gosec
	require.NoError(t, err)

	expectedFileContent, err := os.ReadFile("resources/fixtures/valid.png")
	require.NoError(t, err)

	assert.Equal(t, expectedFileContent, actualFileContent)
}

func TestGenerateTOTPQRCode_Success_JPEG(t *testing.T) {
	t.Parallel()

	actualFile := filepath.Join(t.TempDir(), "qr.jpg")

	account := authenticator.Account{
		Name:       "john.doe@example.com",
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	}

	err := authenticator.GenerateTOTPQRCode(actualFile, account, 200, 200, map[gozxing.EncodeHintType]any{
		gozxing.EncodeHintType_MARGIN: 1,
	})
	require.NoError(t, err)

	actualFileContent, err := os.ReadFile(actualFile) //nolint: gosec
	require.NoError(t, err)

	expectedFileContent, err := os.ReadFile("resources/fixtures/valid.jpg")
	require.NoError(t, err)

	assert.Equal(t, expectedFileContent, actualFileContent)
}

func TestGenerateTOTPQRCode_FailedToOpenFile(t *testing.T) {
	t.Parallel()

	err := authenticator.GenerateTOTPQRCode("/path/to/unknown", authenticator.Account{}, 200, 200)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestGenerateTOTPQRCode_MissingFileExtension(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "qr")

	err := authenticator.GenerateTOTPQRCode(filePath, authenticator.Account{}, 200, 200)
	require.EqualError(t, err, `failed to encode totp qr code: unknown format`)
}

func TestGenerateTOTPQRCode_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "qr.bmp")

	err := authenticator.GenerateTOTPQRCode(filePath, authenticator.Account{}, 200, 200)
	require.EqualError(t, err, `failed to encode totp qr code: unsupported format bmp`)
}

func TestEncodeTOTPQRCode_FailedToGenerateImage(t *testing.T) {
	t.Parallel()

	err := authenticator.EncodeTOTPQRCode(io.Discard, authenticator.Account{}, "", -1, -1)
	require.EqualError(t, err, `failed to encode totp qr code: WriterException: IllegalArgumentException: Requested dimensions are too small: -1x-1`)
}

func TestEncodeTOTPQRCode_FailedToWritePNG(t *testing.T) {
	t.Parallel()

	w := writerFunc(func([]byte) (int, error) {
		return 0, io.ErrShortWrite
	})

	err := authenticator.EncodeTOTPQRCode(w, authenticator.Account{}, "png", 100, 100)
	require.EqualError(t, err, `failed to write totp qr code: short write`)
}

func TestEncodeTOTPQRCode_FailedToWriteJPG(t *testing.T) {
	t.Parallel()

	w := writerFunc(func([]byte) (int, error) {
		return 0, io.ErrShortWrite
	})

	err := authenticator.EncodeTOTPQRCode(w, authenticator.Account{}, "jpg", 100, 100)
	require.EqualError(t, err, `failed to write totp qr code: short write`)
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}
