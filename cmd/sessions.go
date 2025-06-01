package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/davidallendj/magellan/internal/util"
	"github.com/davidallendj/magellan/pkg/secrets"
	"github.com/davidallendj/magellan/pkg/sessions"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stmcginnis/gofish/redfish"
)

var (
	sessionID           string
	sessionToken        string
	sessionTokenPath    string
	sessionOutputFormat string
	storeToken          bool
)

var sessionCmd = &cobra.Command{
	Use: "sessions",
	Example: `  # use BMC credentials to get session token
  magellan sessions login $bmc_host -u $bmc_username -p $bmc_password

  # show active available sessions
  magellan sessions
  magellan sessions list

  # show session tokens in secrets store using host
  magellan secrets retrieve $bmc_host
  magellan secrets list

  # delete an active session (requires a token)
  magellan sessions delete --session-id $SESSION_ID --session-token $SESSION_TOKEN

  # delete an active session (token stored in secrets store)
  magellan sessions delete --session-id $SESSION_ID --secrets-file secrets.json`,
	Short: "Manage sessions with BMCs",
	Long:  "Manage sessions with BMCs. Session tokens can be stored in the secrets store if the MASTER_KEY environment variable is set.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

var sessionLoginCmd = &cobra.Command{
	Use: "login [hosts...]",
	Example: `  // generate the MASTER_KEY for the secret store
  export MASTER_KEY=(magellan secrets generatekey)

  // create a new session by logging into BMC with creds
  magellan sessions login https://bmc_host -u $bmc_username $bmc_password`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Log into a BMC for a session token.",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		// require the MASTER_KEY and secret store to store creds
		var masterKey = os.Getenv("MASTER_KEY")
		if !validSecretArgs(masterKey, secretsFile) {
			log.Error().Str("key", masterKey).Str("secrets-file", secretsFile).Msg("requires MASTER_KEY environment variable to be set with a secrets store")
			os.Exit(1)
		}

		newSessions := []*redfish.Session{}
		for _, host := range args {
			// log into the BMC to create new session
			store := initSecretsStore(host)
			session, sessionToken, err := sessions.Login(host, store)
			if err != nil {
				log.Error().Err(err).Msg("failed to get session token")
				continue
			}
			if sessionToken != "" {
				log.Debug().
					Str("session-token", sessionToken).
					Str("host", host).
					Msg("got session token successfully")
			} else {
				log.Warn().
					Str("host", host).
					Msg("no session token retrieved")
				continue
			}

			newSessions = append(newSessions, session)

			// get the currently existing secrets to update for host
			secret, err := store.GetSecretByID(host)
			if err != nil {
				log.Warn().Err(err).Str("session-id", session.ID).Msg("could not get secret for host")

				// no secret found so create a new one and continue
				newSecret, err := json.Marshal(map[string]any{
					"session-tokens": map[string]string{
						session.ID: sessionToken,
					},
				})
				err = store.StoreSecretByID(host, string(newSecret))
				if err != nil {
					log.Error().Err(err).Str("secret_id", host).Msg("failed to store secret by ID")
				}
				continue
			}

			// secret should be JSON so try and unmarshal and update
			updated, err := util.UpdateJSON([]byte(secret), "", util.JSONObject{})
			if err != nil {
				log.Warn().Err(err).Str("host", host).Msg("failed to update secret")
				continue
			}

			// store the session ID in secrets store for the host
			err = store.StoreSecretByID(host, string(updated))
			if err != nil {
				log.Warn().Err(err).Str("host", host).Msg("could not store the updated secret")
			}
		}

		if len(newSessions) == 0 {
			log.Warn().Msg("no new sessions created")
			os.Exit(0)
		}

		// print the session IDs for created sessions
		switch sessionOutputFormat {
		case "list":
			for _, session := range newSessions {
				fmt.Println(session.ID)
			}
		case "json":
			util.PrintJSON(newSessions)
		case "yaml":
			util.PrintYAML(newSessions)
		default:
			log.Error().Msg("unrecognized output sessionOutputFormat")
			os.Exit(1)
		}
	},
}

var sessionLogoutCmd = &cobra.Command{
	Use: "logout",
	Example: `  // logout of session using a session token
  magellan sessions logout https://172.21.0.2 --session-id 2JFKD

  // log out of session using BMC credentails
  magellan session logout https://172.21.0.2 --session-id 2JFKD -u $bmc_username -p $bmc_password`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Log out of an active session",
	Long:  "Log out of an active session. Session tokens will always be used first if the SESSION_TOKEN environment variable is set.",
	Run: func(cmd *cobra.Command, args []string) {
		for _, host := range args {
			// try to log out with session token if set
			// var err error
			// sessionToken, err = auth.LoadSessionToken(sessionTokenPath)
			// if err != nil {
			// 	log.Warn().Err(err).Str("host", host).Msg("could not load session token from file")
			// }

			// err := sessions.LogoutWithToken(host, sessionID, sessionToken, insecure)
			// if err != nil {
			// 	log.Warn().Err(err).Str("host", host).Msg("could not log out of session with token...trying with credentials")
			// }

			// log out of the sessions for specified host
			store := initSecretsStore(host)
			err := sessions.Logout(host, sessionID, store, insecure)
			if err != nil {
				log.Error().Err(err).Str("host", host).Msg("failed to log out of session")
				os.Exit(1)
			}

			// TODO: remove the session token from the secret store
			masterKey := os.Getenv("MASTER_KEY")
			if validSecretArgs(masterKey, secretsFile) {
				store, err := secrets.OpenStore(secretsFile)
				if err != nil {
					log.Error().Err(err).Str("host", host).Msg("failed to open secret store to remove session token")
					continue
				}

				// get the secrets for the specified host
				secretValue, err := store.GetSecretByID(host)
				if err != nil {
					log.Error().Err(err).Str("host", host).Msg("failed to get secret for host")
					continue
				}

				// unmarshal creds into a map to remove session token
				creds := map[string]any{}
				err = json.Unmarshal([]byte(secretValue), &creds)
				if err != nil {
					log.Error().Err(err).Str("host", host).Msg("failed to unmarshal secret")
					continue
				}

				// remove only the specific session ID and tokens
				sessions, ok := creds["sessions"]
				if ok {
					switch sessions.(type) {
					case map[string]string:
						delete(sessions.(map[string]string), sessionID)
					}
				}

				// update the secrets by storing again
				creds["sessions"] = sessions
				newCreds, err := json.Marshal(creds)
				if err != nil {
					log.Error().Err(err).Str("host", host).Msg("failed to marshal new secrets")
					continue
				}
				store.StoreSecretByID(host, string(newCreds))

			}
		}
	},
}

var sessionStatusCmd = &cobra.Command{
	Use: "status",
	Example: `  // show the host's session service status in YAML sessionOutputFormat
  magellan sessions status https://172.21.0.2:5000 -u $bmc_username -p $bmc_password -i -F yaml`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Show the status of the session service",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		for _, host := range args {
			store := initSecretsStore(host)
			status, err := sessions.GetServiceStatus(host, store, insecure)
			if err != nil {
				log.Error().Err(err).Str("host", host).Msg("failed to get session service status")
				os.Exit(1)
			}

			// show the service status in given sessionOutputFormat
			switch sessionOutputFormat {
			case FORMAT_LIST:
				fmt.Printf("%s: %v (%d secs)", host, status.Enabled, status.Timeout)
			case FORMAT_JSON:
				util.PrintJSON(util.JSONObject{host: status})
			case FORMAT_YAML:
				util.PrintYAML(util.JSONObject{host: status})
			}
		}
	},
}

var sessionListCmd = &cobra.Command{
	Use: "list",
	Example: `  # show active sessions and tokens
  magellan sessions list`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Show a list of active session and tokens",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		// show all of the session IDs then exit
		for _, host := range args {
			store := initSecretsStore(host)
			if sessionID != "" {
				session, err := sessions.GetSession(sessionID, host, store, insecure)
				if err != nil {
					log.Error().
						Err(err).
						Str("host", host).
						Str("session-id", sessionID).
						Msg("failed to get session with ID for host")
					continue
				}

				switch sessionOutputFormat {
				case FORMAT_LIST:
					fallthrough
				case FORMAT_JSON:
					util.PrintJSON(session)
				case FORMAT_YAML:
					util.PrintYAML(session)
				default:
					log.Error().Msg("unrecognized output sessionOutputFormat")
					os.Exit(1)
				}

			} else {
				sessionIDs, err := sessions.GetSessionIDs(host, store, insecure)
				if err != nil {
					log.Error().
						Err(err).
						Str("host", host).
						Msg("failed to get session ID for host")
					continue
				}
				if len(sessionIDs) == 0 {
					log.Warn().
						Str("host", host).
						Msg("no session IDs found for host")
					continue
				}

				switch sessionOutputFormat {
				case FORMAT_LIST:
					fmt.Println(strings.Join(sessionIDs, "\n"))
				case FORMAT_JSON:
					util.PrintJSON(sessionIDs)
				case FORMAT_YAML:
					util.PrintYAML(sessionIDs)
				default:
					log.Error().Msg("unrecognized output sessionOutputFormat")
					os.Exit(1)
				}
			}
		}
	},
}

func init() {

	// sessionLoginCmd.Flags().BoolVarP(&insecure, "insecure", "i", false, "Skip TLS verification")

	sessionLoginCmd.Aliases = append(sessionLoginCmd.Aliases, "new", "create", "add")

	sessionLogoutCmd.Flags().StringVar(&sessionID, "session-id", "", "Set the session ID to end session")
	// sessionLogoutCmd.Flags().StringVar(&sessionToken, "session-token", "", "Set the session token used to log out of session (can also be set with the SESSION_TOKEN environment variable)")

	sessionLogoutCmd.MarkFlagRequired("session-id")
	sessionLogoutCmd.Aliases = append(sessionCmd.Aliases, "delete", "remove")

	sessionListCmd.Flags().StringVar(&sessionID, "session-id", "", "Show more information for specified session")
	sessionListCmd.Flags().StringVar(&secretsFile, "secrets-file", "secrets.json", "Set the path to secrets store file to store credentials")

	sessionCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "i", false, "Skip TLS verification")
	sessionCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "Set the username for BMC login")
	sessionCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Set the password for BMC login")
	sessionCmd.PersistentFlags().StringVar(&sessionTokenPath, "session-token-file", "", "Set the session token from a file")
	sessionCmd.PersistentFlags().StringVar(&sessionToken, "session-token", "", "Set the session token")
	sessionCmd.PersistentFlags().StringVarP(&sessionOutputFormat, "sessionOutputFormat", "F", "list", "Set the output sessionOutputFormat (list|json|yaml)")
	sessionCmd.PersistentFlags().StringVarP(&secretsFile, "secrets-file", "f", "secrets.json", "Set the path to secrets store file to store credentials")

	sessionCmd.MarkFlagRequired("username")
	sessionCmd.MarkFlagRequired("password")
	sessionCmd.MarkFlagsRequiredTogether("username", "password")
	sessionCmd.MarkFlagsMutuallyExclusive("session-token", "session-token-file")

	sessionCmd.AddCommand(sessionLoginCmd, sessionLogoutCmd, sessionListCmd, sessionStatusCmd)
	rootCmd.AddCommand(sessionCmd)
}
