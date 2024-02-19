package authenticator_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.nhat.io/otp"
	"go.nhat.io/secretstorage"
	mockss "go.nhat.io/secretstorage/mock"

	"go.nhat.io/authenticator"
)

func TestNamespace_Marshal(t *testing.T) {
	n := authenticator.Namespace{
		Name:     "namespace",
		Accounts: []string{"john.doe@example.com"},
	}

	err := n.UnmarshalText([]byte(`{`))
	require.EqualError(t, err, `failed to unmarshal namespace: toml: invalid character at start of key: {`)

	d, err := n.MarshalText()
	require.NoError(t, err)

	n2 := authenticator.Namespace{}
	err = n2.UnmarshalText(d)

	require.NoError(t, err)

	require.Equal(t, n, n2)
}

func TestGetAllNamespaceIDs(t *testing.T) {
	setConfigFile(t)

	actual, err := authenticator.GetAllNamespaceIDs()
	require.NoError(t, err)

	require.Empty(t, actual)

	err = authenticator.CreateNamespace("namespaceB", "B")
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace("namespaceB")
		require.NoError(t, err)
	})

	err = authenticator.CreateNamespace("namespaceA", "A")
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace("namespaceA")
		require.NoError(t, err)
	})

	actual, err = authenticator.GetAllNamespaceIDs()
	require.NoError(t, err)

	expected := []string{"namespaceA", "namespaceB"}

	require.Equal(t, expected, actual)
}

func TestGetNamespace_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)
	})

	actual, err := authenticator.GetNamespace(t.Name())
	require.NoError(t, err)

	expected := authenticator.Namespace{
		Name:     t.Name(),
		Accounts: []string{"john.doe@example.com"},
	}

	require.Equal(t, expected, actual)
}

func TestGetNamespace_NotFound(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	actual, err := authenticator.GetNamespace(t.Name())
	require.EqualError(t, err, `failed to get namespace TestGetNamespace_NotFound: namespace not found`)
	assert.Empty(t, actual)
}

func TestGetNamespace_Failed(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, assert.AnError)
	})

	actual, err := authenticator.GetNamespace(t.Name())
	require.EqualError(t, err, `failed to get namespace TestGetNamespace_Failed: assert.AnError general error for testing`)
	assert.Empty(t, actual)
}

func TestCreateNamespace_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})
}

func TestCreateNamespace_InConfig(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err = authenticator.CreateNamespace(t.Name(), t.Name())
	require.EqualError(t, err, `namespace already exists: TestCreateNamespace_InConfig`)
}

func TestCreateNamespace_NotInConfig_InStorage(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, nil)
	})

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.EqualError(t, err, `namespace already exists in storage: TestCreateNamespace_NotInConfig_InStorage`)
}

func TestCreateNamespace_FailedToCreate(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(assert.AnError)
	})

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.EqualError(t, err, `failed to create namespace TestCreateNamespace_FailedToCreate: assert.AnError general error for testing`)
}

func TestUpdateNamespace_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{
			Name:     t.Name(),
			Accounts: []string{"john.doe@example.com"},
		}).
			Return(nil)
	})

	err := authenticator.UpdateNamespace(t.Name(), authenticator.Namespace{
		Name:     t.Name(),
		Accounts: []string{"john.doe@example.com"},
	})
	require.NoError(t, err)
}

func TestUpdateNamespace_Failed(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(assert.AnError)
	})

	err := authenticator.UpdateNamespace(t.Name(), authenticator.Namespace{})
	require.EqualError(t, err, `failed to update namespace TestUpdateNamespace_Failed: assert.AnError general error for testing`)
}

func TestDeleteNamespace_NoAccounts_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	err = authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_NoAccounts_FailedToLoadConfig(t *testing.T) {
	setConfigFileWithContent(t, "{")

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to decode config file: toml: invalid character at start of key: {`)
}

func TestDeleteNamespace_NoAccounts_FailedToLoadNamespaceConfig(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, assert.AnError)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to get namespace for deletion: assert.AnError general error for testing`)
}

func TestDeleteNamespace_NoAccounts_NamespaceConfigNotFound(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_NoAccounts_InConfig_Success(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(nil)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_NoAccounts_InConfig_NotInStorage(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_NoAccounts_InConfig_Failed(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(assert.AnError)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to delete namespace: assert.AnError general error for testing`)
}

func TestDeleteNamespace_NoAccounts_NotInConfig_Success(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(nil)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err, nil)
}

func TestDeleteNamespace_NoAccounts_NotInConfig_NotInStorage(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err, nil)
}

func TestDeleteNamespace_NoAccounts_NotInConfig_Failed(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(assert.AnError)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to delete namespace: assert.AnError general error for testing`)
}

func TestDeleteNamespace_HasAccounts_Success(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteNamespace_HasAccounts_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_HasAccounts_FailedToDeleteTOTPSecret(t *testing.T) {
	setConfigFileWithContent(t, fmt.Sprintf(`namespaces = [%q]`, t.Name()))

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Delete", "go.nhat.io/authenticator", t.Name()).
			Return(nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteNamespace_HasAccounts_FailedToDeleteTOTPSecret/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to delete TOTP secret of john.doe@example.com: assert.AnError general error for testing`)
}

func TestAddAccountToNamespace_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err = authenticator.AddAccountToNamespace(t.Name(), "john.doe@example.com")
	require.NoError(t, err)

	err = authenticator.AddAccountToNamespace(t.Name(), "jane.doe@example.com")
	require.NoError(t, err)

	actual, err := authenticator.GetNamespace(t.Name())
	require.NoError(t, err)

	expected := authenticator.Namespace{
		Name: t.Name(),
		Accounts: []string{
			"jane.doe@example.com",
			"john.doe@example.com",
		},
	}

	require.Equal(t, expected, actual)
}

func TestAddAccountToNamespace_AccountAddedMoreThanOnce(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	const account = "john.doe@example.com"

	err = authenticator.AddAccountToNamespace(t.Name(), account)
	require.NoError(t, err)

	err = authenticator.AddAccountToNamespace(t.Name(), account)
	require.NoError(t, err)

	actual, err := authenticator.GetNamespace(t.Name())
	require.NoError(t, err)

	expected := authenticator.Namespace{
		Name:     t.Name(),
		Accounts: []string{"john.doe@example.com"},
	}

	require.Equal(t, expected, actual)
}

func TestAddAccountToNamespace_NamespaceNotExists(t *testing.T) {
	err := authenticator.AddAccountToNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, `failed to get namespace TestAddAccountToNamespace_NamespaceNotExists: namespace not found`)
}

func TestAddAccountToNamespace_FailedToUpdateNamespace(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), authenticator.Namespace{Name: t.Name()}).
			Return(nil)

		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{Name: t.Name()}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(),
			authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}).
			Return(assert.AnError)
	})

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	err = authenticator.AddAccountToNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, `failed to update namespace TestAddAccountToNamespace_FailedToUpdateNamespace: assert.AnError general error for testing`)
}

func TestDeleteAccountInNamespace_CouldNotGetNamespace(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to get namespace TestDeleteAccountInNamespace_CouldNotGetNamespace: namespace not found")
}

func TestDeleteAccountInNamespace_HasAccount_CouldNotUpdateNamespace(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete account john.doe@example.com in namespace: assert.AnError general error for testing")
}

func TestDeleteAccountInNamespace_HasAccount_CouldNotDeleteTOTPSecret(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteAccountInNamespace_HasAccount_CouldNotDeleteTOTPSecret/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete TOTP secret of john.doe@example.com: assert.AnError general error for testing")
}

func TestDeleteAccountInNamespace_HasAccount_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteAccountInNamespace_HasAccount_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.NoError(t, err)
}

func TestDeleteAccountInNamespace_NoAccount_CouldNotDeleteTOTPSecret(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name: t.Name(),
			}, nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteAccountInNamespace_NoAccount_CouldNotDeleteTOTPSecret/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete TOTP secret of john.doe@example.com: assert.AnError general error for testing")
}

func TestDeleteAccountInNamespace_NoAccount_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name: t.Name(),
			}, nil)
	})

	setTOTPSecretStorage(t, func(s *mockss.Storage[otp.TOTPSecret]) {
		s.On("Delete", "go.nhat.io/totp", "TestDeleteAccountInNamespace_NoAccount_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteAccountInNamespace(t.Name(), "john.doe@example.com")
	require.NoError(t, err)
}

func TestDeleteAccountInNamespace_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err = authenticator.AddAccountToNamespace(t.Name(), "john.doe@example.com")
	require.NoError(t, err)

	err = authenticator.SetTOTPSecret(t.Name(), "john.doe@example.com", "NBSWY3DP")
	require.NoError(t, err)
}

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

func setNamespaceStorage(t *testing.T, mocks ...func(s *mockss.Storage[authenticator.Namespace])) {
	t.Helper()

	s := mockss.MockStorage[authenticator.Namespace](mocks...)(t)
	reset := authenticator.SetNamespaceStorage(s)

	t.Cleanup(reset)
}

func setTOTPSecretStorage(t *testing.T, mocks ...func(s *mockss.Storage[otp.TOTPSecret])) {
	t.Helper()

	s := mockss.MockStorage[otp.TOTPSecret](mocks...)(t)
	reset := authenticator.SetTOTPSecretStorage(s)

	t.Cleanup(reset)
}
