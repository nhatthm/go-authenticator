package authenticator

import (
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"go.nhat.io/otp"
)

var (
	// ErrUnknownFormat indicates that the format is unknown.
	ErrUnknownFormat = fmt.Errorf("unknown format")
	// ErrUnsupportedFormat indicates that the format is unsupported.
	ErrUnsupportedFormat = fmt.Errorf("unsupported format")
)

const (
	totpAuthProtocol    = "otpauth://totp/"
	totpAuthSecretParam = "secret"
	totpAuthIssuerParam = "issuer"
)

// ParseTOTPQRCode decodes a TOTP QR code from the given file path.
func ParseTOTPQRCode(path string) (Account, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return Account{}, fmt.Errorf("failed to qr code file: %w", err)
	}

	defer f.Close() //nolint: errcheck,gosec

	return DecodeTOTPQRCode(f)
}

// GenerateTOTPQRCode generates a TOTP QR code for the given account.
func GenerateTOTPQRCode(path string, account Account, width, height int, listOfHints ...map[gozxing.EncodeHintType]any) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint: mnd
	if err != nil {
		return fmt.Errorf("failed to create qr code file: %w", err)
	}

	defer f.Close() //nolint: errcheck,gosec

	return EncodeTOTPQRCode(f, account, strings.TrimPrefix(filepath.Ext(path), "."), width, height, listOfHints...)
}

// DecodeTOTPQRCode decodes a TOTP QR code from the given file path.
func DecodeTOTPQRCode(r io.Reader) (Account, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return Account{}, fmt.Errorf("failed to decode image: %w", err)
	}

	bmp, _ := gozxing.NewBinaryBitmapFromImage(img) //nolint: errcheck
	qrReader := qrcode.NewQRCodeReader()

	result, err := qrReader.Decode(bmp, nil)
	if err != nil {
		return Account{}, fmt.Errorf("failed to decode qr code: %w", err)
	}

	if !strings.Contains(result.String(), totpAuthProtocol) {
		return Account{}, fmt.Errorf("invalid totpauth uri: %s", result.String()) //nolint: err113
	}

	u, err := url.Parse(result.String())
	if err != nil {
		return Account{}, fmt.Errorf("failed to parse otpauth uri: %w", err)
	}

	account := Account{
		Name:       strings.Trim(u.Path, "/"),
		TOTPSecret: otp.TOTPSecret(u.Query().Get(totpAuthSecretParam)),
		Issuer:     u.Query().Get(totpAuthIssuerParam),
		Metadata:   nil,
	}

	return account, nil
}

// EncodeTOTPQRCode produces a TOTP QR code for the given account.
func EncodeTOTPQRCode(w io.Writer, account Account, format string, width, height int, listOfHints ...map[gozxing.EncodeHintType]any) error {
	params := url.Values{}
	params.Set(totpAuthSecretParam, account.TOTPSecret.String())
	params.Set(totpAuthIssuerParam, account.Issuer)

	u, _ := url.Parse(totpAuthProtocol) //nolint: errcheck
	u.Path = account.Name
	u.RawQuery = params.Encode()

	qrWriter := qrcode.NewQRCodeWriter()
	totpAuthURI := u.String()

	encodeHints := map[gozxing.EncodeHintType]any{
		gozxing.EncodeHintType_MARGIN: 0,
	}

	for _, hints := range listOfHints {
		for k, v := range hints {
			encodeHints[k] = v
		}
	}

	bmp, err := qrWriter.Encode(totpAuthURI, gozxing.BarcodeFormat_QR_CODE, width, height, encodeHints)
	if err != nil {
		return fmt.Errorf("failed to encode totp qr code: %w", err)
	}

	switch format {
	case "png":
		err = png.Encode(w, bmp)

	case "jpg", "jpeg":
		err = jpeg.Encode(w, bmp, &jpeg.Options{Quality: 100})

	case "":
		return fmt.Errorf("failed to encode totp qr code: %w", ErrUnknownFormat)

	default:
		return fmt.Errorf("failed to encode totp qr code: %w %s", ErrUnsupportedFormat, format)
	}

	if err != nil {
		return fmt.Errorf("failed to write totp qr code: %w", err)
	}

	return nil
}
