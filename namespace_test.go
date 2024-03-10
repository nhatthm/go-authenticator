package authenticator_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.nhat.io/secretstorage"
	mockss "go.nhat.io/secretstorage/mock"

	"go.nhat.io/authenticator"
)

func TestNamespace_Marshal(t *testing.T) {
	expected := authenticator.Namespace{
		Name:     "namespace",
		Accounts: []string{"john.doe@example.com"},
	}

	data, err := json.Marshal(expected)
	require.NoError(t, err)

	var actual authenticator.Namespace

	err = json.Unmarshal(data, &actual)
	require.NoError(t, err)

	require.Equal(t, expected, actual)
}

func TestNamespace_UnmarshalText_Error(t *testing.T) {
	t.Parallel()

	var actual authenticator.Namespace

	err := actual.UnmarshalText([]byte(`"{"`))

	require.EqualError(t, err, `failed to unmarshal namespace: json: cannot unmarshal string into Go value of type authenticator.namespace`)
	assert.Empty(t, actual)
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

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteNamespace_HasAccounts_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.NoError(t, err)
}

func TestDeleteNamespace_HasAccounts_FailedToDeleteAccount(t *testing.T) {
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

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteNamespace_HasAccounts_FailedToDeleteAccount/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteNamespace(t.Name())
	require.EqualError(t, err, `failed to delete account john.doe@example.com: assert.AnError general error for testing`)
}

func setNamespaceStorage(t *testing.T, mocks ...func(s *mockss.Storage[authenticator.Namespace])) {
	t.Helper()

	s := mockss.MockStorage[authenticator.Namespace](mocks...)(t)
	reset := authenticator.SetNamespaceStorage(s)

	t.Cleanup(reset)
}
