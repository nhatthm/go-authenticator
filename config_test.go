package authenticator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func setConfigFile(t *testing.T) {
	t.Helper()

	setConfigFileWithContent(t, "")
}

func setConfigFileWithContent(t *testing.T, content string) {
	t.Helper()

	file := filepath.Join(t.TempDir(), ".authenticator.toml")

	if len(content) > 0 {
		err := os.WriteFile(file, []byte(content), 0o600)
		require.NoError(t, err)
	}

	t.Setenv("AUTHENTICATOR_CONFIG", file)
}
