package auth

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// LoadAccessToken() tries to load a JWT string from an environment
// variable, file, or config in that order. If loading the token
// fails with one options, it will fallback to the next option until
// all options are exhausted.
//
// NOTE: Access tokens expire after a set period. Inspect the token
// and check the `exp` claim to see if the token is expired.
//
// Returns a token as a string with no error if successful.
// Alternatively, returns an empty string with an error if a token is
// not able to be loaded.
func LoadAccessToken(path string) (string, error) {
	// try to load token from env var
	testToken := os.Getenv("ACCESS_TOKEN")
	if testToken != "" {
		return testToken, nil
	}

	// try reading access token from a file
	b, err := os.ReadFile(path)
	if err == nil {
		return string(b), nil
	}

	// TODO: try to load token from config
	testToken = viper.GetString("access-token")
	if testToken != "" {
		return testToken, nil
	}
	return "", fmt.Errorf("failed to load access token from environment variable, file, or config")
}

// LoadSessionToken() behaves similarly to LoadAccessToken() by
// trying to load a session token for BMC authentication. Session
// authentication is preferred over using basic authentication to
// reduce the overhead caused by performing a login. This method
// tries to load from an SESSION_TOKEN environment variable first,
// then a file specified by the path, then from the "access-token"
// property in the config file.
//
// NOTE: Like access tokens, session tokens expired after a given
// time period if not used.
//
// Returns a session token as a string with no error if successful.
func LoadSessionToken(path string) (string, error) {
	// try to load token from env var
	testToken := os.Getenv("SESSION_TOKEN")
	if testToken != "" {
		return testToken, nil
	}

	// try reading access token from a file
	b, err := os.ReadFile(path)
	if err == nil {
		return string(b), nil
	}

	// TODO: try to load token from config
	testToken = viper.GetString("session-token")
	if testToken != "" {
		return testToken, nil
	}
	return "", fmt.Errorf("failed to load session token from environment variable, file, or config")
}
