package sessions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/davidallendj/magellan/internal/util"
	"github.com/davidallendj/magellan/pkg/bmc"
	"github.com/davidallendj/magellan/pkg/client"
	"github.com/davidallendj/magellan/pkg/secrets"
	"github.com/stmcginnis/gofish"
	"github.com/stmcginnis/gofish/redfish"
)

type Params struct {
	Host         string
	Username     string
	Password     string
	SessionID    string
	SessionToken string
}

type ServiceStatus struct {
	Enabled bool
	Timeout int
}

// Login() makes a single POST to the /redfish/v1/SessionService/Session endpoint to obtain a session token that can used for subsequent calls to the BMC. Using the SessionService reduces the overhead associated with logging into the BMC.
//
// Returns session ID, session token (X-AUTH-TOKEN), and/or error.
func Login(host string, store secrets.SecretStore) (*redfish.Session, string, error) {
	var (
		c       client.DefaultClient
		body    client.HTTPBody
		res     *http.Response
		encoded string
		err     error
	)

	creds, err := loadBMCCreds(host, store)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load BMC credentials: %v", err)
	}

	encoded = base64.StdEncoding.EncodeToString(fmt.Appendf([]byte{}, "%s:%s", creds.Username, creds.Password))
	res, body, err = client.MakeRequest(c.Client,
		host+"/redfish/v1/SessionService/Sessions",
		http.MethodPost,
		client.HTTPBody(fmt.Sprintf("{\"UserName\": \"%s\", \"Password\": \"%s\"}", creds.Username, creds.Password)),
		client.HTTPHeader{
			"Authorization": fmt.Sprintf("Basic %s", encoded),
			"Content-Type":  "application/json",
		})
	if err != nil {
		return nil, "", fmt.Errorf("failed to make request to session service: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("response returned status code %d", res.StatusCode)
	}

	// extract the session endpoint from body if JSON
	obj, err := util.FromJSON(body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal JSON from session login response: %v", err)
	}

	// make a request to endpoint to get session data
	endpoint, ok := obj["message"]
	session := &redfish.Session{}
	if ok {
		switch endpoint.(type) {
		case string:
			_, body, err := client.MakeRequest(c.Client, host+endpoint.(string), http.MethodGet, nil, nil)
			if err != nil {
				return nil, "", fmt.Errorf("failed to make request for session token for host '%s': %v", host, err)
			}

			err = json.Unmarshal(body, &session)
			if err != nil {
				return nil, "", fmt.Errorf("failed to unmarshal response from session request for host '%s': %v", host, err)
			}
		}
	} else {
		return nil, "", fmt.Errorf("failed to extract session token from response JSON")
	}

	// extract the X-AUTH-TOKEN from the response header
	return session, res.Header.Get("X-Auth-Token"), nil
}

func Logout(host string, sessionID string, store secrets.SecretStore, insecure bool) error {
	creds, err := loadBMCCreds(host, store)
	if err != nil {
		return fmt.Errorf("failed to load BMC credentials: %v", err)
	}

	// initialize gofish client
	client, err := gofish.Connect(gofish.ClientConfig{
		Endpoint:  host,
		Insecure:  insecure,
		Username:  creds.Username,
		Password:  creds.Password,
		BasicAuth: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to BMC: %v", err)
	}
	defer client.Logout()

	res, err := client.Delete("/redfish/v1/SessionService/Sessions/" + sessionID)
	if err != nil {
		return fmt.Errorf("failed to make request to delete session: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("response to delete session returned code %d", res.StatusCode)
	}

	return nil
}

func LogoutWithToken(host string, sessionID string, sessionToken string, insecure bool) error {
	// initialize gofish client
	client, err := gofish.Connect(gofish.ClientConfig{
		Endpoint:  host,
		Insecure:  insecure,
		BasicAuth: false,
		Session: &gofish.Session{
			ID:    sessionID,
			Token: sessionToken,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to connect to BMC: %v", err)
	}
	defer client.Logout()
	client.Delete(host + "/redfish/v1/SessionService/Sessions/" + sessionID)
	return nil
}

func GetServiceStatus(host string, store secrets.SecretStore, insecure bool) (*ServiceStatus, error) {
	creds, err := loadBMCCreds(host, store)
	if err != nil {
		return nil, fmt.Errorf("failed to load BMC credentials: %v", err)
	}
	// initialize gofish client
	client, err := gofish.Connect(gofish.ClientConfig{
		Endpoint:  host,
		Username:  creds.Username,
		Password:  creds.Password,
		Insecure:  insecure,
		BasicAuth: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to BMC: %v", err)
	}
	defer client.Logout()
	sessionService, err := client.GetService().SessionService()
	if err != nil {
		return nil, fmt.Errorf("failed to get session service: %v", err)
	}

	return &ServiceStatus{
		Enabled: sessionService.ServiceEnabled,
		Timeout: sessionService.SessionTimeout,
	}, nil
}

func GetSessionIDs(host string, store secrets.SecretStore, insecure bool) ([]string, error) {

	sessions, err := getSessions(host, store, insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to get the active session IDs from the session service: %v", err)
	}

	sessionIDs := []string{}
	for _, session := range sessions {
		sessionIDs = append(sessionIDs, session.ID)
	}

	return sessionIDs, nil
}

func GetSession(id string, host string, store secrets.SecretStore, insecure bool) (*redfish.Session, error) {
	// get all of the sessions from the BMC node
	sessions, err := getSessions(host, store, insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to get the active session IDs from the session service: %v", err)
	}

	// now, only return the one that we want using the session ID
	index := slices.IndexFunc(sessions, func(item *redfish.Session) bool {
		return id == item.ID
	})
	if index >= 0 {
		return sessions[index], nil
	}

	// we didn't find anything so return error
	return nil, fmt.Errorf("could not find session")
}

func getSessions(host string, store secrets.SecretStore, insecure bool) ([]*redfish.Session, error) {
	creds, err := loadBMCCreds(host, store)
	if err != nil {
		return nil, fmt.Errorf("failed to load BMC credentials: %v", err)
	}

	// initialize gofish client
	client, err := gofish.Connect(gofish.ClientConfig{
		Endpoint:  host,
		Username:  creds.Username,
		Password:  creds.Password,
		Insecure:  insecure,
		BasicAuth: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to BMC: %v", err)
	}
	defer client.Logout()

	service, err := client.Service.SessionService()
	if err != nil {
		return nil, fmt.Errorf("failed to get the session service: %v", err)
	}

	return service.Sessions()
}

// SessionLogin() makes a single POST to the /redfish/v1/SessionService/Session using the `gofish` library which can be used for subsequent requests to the BMC.
//
// NOTE: This implementation makes multiple requests to the BMC to obtain the need session token whereas the other implementation makes a single request to the required endpoint.
// func SessionLogin(config crawler.CrawlerConfig) (string, error) {
// 	// get username and password from secret store
// 	bmc_creds, err := crawler.LoadBMCCreds(config)
// 	if err != nil {
// 		event := log.Error()
// 		event.Err(err)
// 		event.Msg("failed to load BMC credentials")
// 		return "", err
// 	}

// 	// initialize gofish client
// 	client, err := gofish.Connect(gofish.ClientConfig{
// 		Endpoint:  config.URI,
// 		Username:  bmc_creds.Username,
// 		Password:  bmc_creds.Password,
// 		Insecure:  config.Insecure,
// 		BasicAuth: true,
// 	})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to connect to BMC: %v")
// 	}

// 	service, err := client.Service.SessionService()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get the session service: %v", err)
// 	}

// 	res, err := service.PostWithResponse(uri string, map[string]any{
// 		"UserName": bmc_creds.Username,
// 		"Password": bmc_creds.Password,
// 	})

// 	// extract the session token from headers
// }

func loadBMCCreds(host string, store secrets.SecretStore) (bmc.BMCCredentials, error) {
	var (
		creds       bmc.BMCCredentials
		secretValue string
		err         error
	)
	// get creds from secret store
	secretValue, err = store.GetSecretByID(host)
	if err != nil {
		return creds, fmt.Errorf("failed to get secret by ID: %v", err)
	}
	err = json.Unmarshal([]byte(secretValue), &creds)
	if err != nil {
		return creds, fmt.Errorf("failed to unmarshal credentials: %v", err)
	}
	return creds, nil
}
