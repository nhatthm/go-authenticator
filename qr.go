package authenticator

import (
	"fmt"
	"image"
	_ "image/jpeg" // Support JPEG images.
	_ "image/png"  // Support PNG images.
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

const (
	totpAuthProtocol    = "otpauth://totp/"
	totpAuthSecretParam = "secret"
	totpAuthIssuerParam = "issuer"
)

// ParseTOTPQRCode parses a TOTP QR code and returns the secret, label, and issuer.
func ParseTOTPQRCode(path string) (secret string, label string, issuer string, err error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to qr code file: %w", err)
	}

	img, _, err := image.Decode(file)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decode image: %w", err)
	}

	bmp, _ := gozxing.NewBinaryBitmapFromImage(img) //nolint: errcheck
	qrReader := qrcode.NewQRCodeReader()

	result, err := qrReader.Decode(bmp, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decode qr code: %w", err)
	}

	if !strings.Contains(result.String(), totpAuthProtocol) {
		return "", "", "", fmt.Errorf("invalid totpauth uri: %s", result.String()) //nolint: goerr113
	}

	u, err := url.Parse(result.String())
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse otpauth uri: %w", err)
	}

	secret = u.Query().Get(totpAuthSecretParam)
	label = strings.Trim(u.Path, "/")
	issuer = u.Query().Get(totpAuthIssuerParam)

	return secret, label, issuer, nil
}
