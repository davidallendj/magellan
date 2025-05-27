package secrets

import "errors"

const DEFAULT_KEY = "default"

var (
	ErrLoadFailedCreds = errors.New("failed to load BMC credentials")
)

type SecretStore interface {
	GetSecretByID(secretID string) (string, error)
	StoreSecretByID(secretID, secret string) error
	ListSecrets() (map[string]string, error)
	RemoveSecretByID(secretID string) error
}
