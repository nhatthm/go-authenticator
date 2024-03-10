package authenticator_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.nhat.io/secretstorage"
	mockss "go.nhat.io/secretstorage/mock"

	"go.nhat.io/authenticator"
)

func TestAccount_MarshalText(t *testing.T) {
	t.Parallel()

	expected := authenticator.Account{
		Name:       "john.doe@example.com",
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
		Metadata:   map[string]any{"message": "foobar"},
	}

	data, err := json.Marshal(expected)
	require.NoError(t, err)

	var actual authenticator.Account

	err = json.Unmarshal(data, &actual)
	require.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestAccount_UnmarshalText_Error(t *testing.T) {
	t.Parallel()

	var actual authenticator.Account

	err := json.Unmarshal([]byte(`"{\"totp_secret\": 123}"`), &actual)

	require.EqualError(t, err, "failed to unmarshal account: json: cannot unmarshal number into Go struct field account.totp_secret of type otp.TOTPSecret")
	assert.Empty(t, actual)
}

func TestAccount_MarshalText_Error(t *testing.T) {
	t.Parallel()

	account := authenticator.Account{
		Metadata: map[string]any{
			"channel": make(chan struct{}),
		},
	}

	actual, err := json.Marshal(account)

	require.EqualError(t, err, "json: error calling MarshalText for type authenticator.Account: failed to marshal account: json: unsupported type: chan struct {}")
	assert.Empty(t, actual)
}

func TestGetAccount_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	const account = "john.doe@example.com"

	err = authenticator.SetAccount(t.Name(), authenticator.Account{
		Name:       account,
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	})
	require.NoError(t, err)

	actual, err := authenticator.GetAccount(t.Name(), account)
	require.NoError(t, err)

	expected := authenticator.Account{
		Name:       account,
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	}

	assert.Equal(t, expected, actual)
}

func TestGetAccount_AccountNotFound(t *testing.T) {
	actual, err := authenticator.GetAccount(t.Name(), "john.doe@example.com")

	require.ErrorIs(t, err, authenticator.ErrAccountNotFound)
	require.EqualError(t, err, `failed to get account john.doe@example.com in namespace TestGetAccount_AccountNotFound: account not found`)
	assert.Empty(t, authenticator.Account{}, actual)
}

func TestGetAccount_StorageError(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Get", "go.nhat.io/authenticator", "TestGetAccount_StorageError/john.doe@example.com").
			Return(authenticator.Account{}, assert.AnError)
	})

	actual, err := authenticator.GetAccount(t.Name(), "john.doe@example.com")

	require.EqualError(t, err, `failed to get account john.doe@example.com in namespace TestGetAccount_StorageError: assert.AnError general error for testing`)
	assert.Empty(t, authenticator.Account{}, actual)
}

func TestSetAccount_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err = authenticator.SetAccount(t.Name(), authenticator.Account{Name: "john.doe@example.com"})
	require.NoError(t, err)

	err = authenticator.SetAccount(t.Name(), authenticator.Account{Name: "jane.doe@example.com"})
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

func TestSetAccount_AccountAddedMoreThanOnce(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	const account = "john.doe@example.com"

	err = authenticator.SetAccount(t.Name(), authenticator.Account{Name: account})
	require.NoError(t, err)

	err = authenticator.SetAccount(t.Name(), authenticator.Account{Name: account})
	require.NoError(t, err)

	actual, err := authenticator.GetNamespace(t.Name())
	require.NoError(t, err)

	expected := authenticator.Namespace{
		Name:     t.Name(),
		Accounts: []string{"john.doe@example.com"},
	}

	require.Equal(t, expected, actual)
}

func TestSetAccount_FailedToSet(t *testing.T) {
	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Set", "go.nhat.io/authenticator", "TestSetAccount_FailedToSet/john.doe@example.com", mock.Anything).
			Return(assert.AnError)
	})

	err := authenticator.SetAccount(t.Name(), authenticator.Account{Name: "john.doe@example.com"})
	require.EqualError(t, err, `failed to create account john.doe@example.com in namespace TestSetAccount_FailedToSet: assert.AnError general error for testing`)
}

func TestSetAccount_NamespaceNotExists(t *testing.T) {
	t.Cleanup(func() {
		err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
		require.NoError(t, err)
	})

	err := authenticator.SetAccount(t.Name(), authenticator.Account{Name: "john.doe@example.com"})
	require.EqualError(t, err, `failed to get namespace TestSetAccount_NamespaceNotExists for creating account john.doe@example.com: namespace not found`)
}

func TestSetAccount_FailedToUpdateNamespace(t *testing.T) {
	setConfigFile(t)

	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{Name: t.Name()}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(),
			authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}).
			Return(assert.AnError)

		// For simplified deletion on cleanup.
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	t.Cleanup(func() {
		err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
		require.NoError(t, err)
	})

	err := authenticator.SetAccount(t.Name(), authenticator.Account{Name: "john.doe@example.com"})
	require.EqualError(t, err, `failed to update namespace TestSetAccount_FailedToUpdateNamespace: assert.AnError general error for testing`)
}

func TestDeleteAccount_FailedToGetNamespace(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, assert.AnError)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, `failed to get namespace TestDeleteAccount_FailedToGetNamespace for deleting account john.doe@example.com: assert.AnError general error for testing`)
}

func TestDeleteAccount_NamespaceNotFound_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_NamespaceNotFound_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.NoError(t, err)
}

func TestDeleteAccount_NamespaceNotFound_FailedToDelete(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).Once().
			Return(authenticator.Namespace{}, secretstorage.ErrNotFound)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_NamespaceNotFound_FailedToDelete/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete account john.doe@example.com in namespace TestDeleteAccount_NamespaceNotFound_FailedToDelete: assert.AnError general error for testing")
}

func TestDeleteAccount_HasAccount_CouldNotUpdateNamespace(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to remove account john.doe@example.com from namespace TestDeleteAccount_HasAccount_CouldNotUpdateNamespace: assert.AnError general error for testing")
}

func TestDeleteAccount_HasAccount_FailedToDelete(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_HasAccount_FailedToDelete/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete account john.doe@example.com in namespace TestDeleteAccount_HasAccount_FailedToDelete: assert.AnError general error for testing")
}

func TestDeleteAccount_HasAccount_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name:     t.Name(),
				Accounts: []string{"john.doe@example.com"},
			}, nil)

		s.On("Set", "go.nhat.io/authenticator", t.Name(), mock.Anything).
			Return(nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_HasAccount_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.NoError(t, err)
}

func TestDeleteAccount_NoAccount_FailedToDelete(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name: t.Name(),
			}, nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_NoAccount_FailedToDelete/john.doe@example.com").
			Return(assert.AnError)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.EqualError(t, err, "failed to delete account john.doe@example.com in namespace TestDeleteAccount_NoAccount_FailedToDelete: assert.AnError general error for testing")
}

func TestDeleteAccount_NoAccount_Success(t *testing.T) {
	setNamespaceStorage(t, func(s *mockss.Storage[authenticator.Namespace]) {
		s.On("Get", "go.nhat.io/authenticator", t.Name()).
			Return(authenticator.Namespace{
				Name: t.Name(),
			}, nil)
	})

	setAccountStorage(t, func(s *mockss.Storage[authenticator.Account]) {
		s.On("Delete", "go.nhat.io/authenticator", "TestDeleteAccount_NoAccount_Success/john.doe@example.com").
			Return(nil)
	})

	err := authenticator.DeleteAccount(t.Name(), "john.doe@example.com")
	require.NoError(t, err)
}

func TestDeleteAccount_Success(t *testing.T) {
	setConfigFile(t)

	err := authenticator.CreateNamespace(t.Name(), t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		err := authenticator.DeleteNamespace(t.Name())
		require.NoError(t, err)
	})

	err = authenticator.SetAccount(t.Name(), authenticator.Account{
		Name:       "john.doe@example.com",
		TOTPSecret: "NBSWY3DP",
		Issuer:     "example.com",
	})
	require.NoError(t, err)
}

func setAccountStorage(t *testing.T, mocks ...func(s *mockss.Storage[authenticator.Account])) {
	t.Helper()

	s := mockss.MockStorage[authenticator.Account](mocks...)(t)
	reset := authenticator.SetAccountStorage(s)

	t.Cleanup(reset)
}
