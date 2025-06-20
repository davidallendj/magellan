// The cmd package implements the interface for the magellan CLI. The files
// contained in this package only contains implementations for handling CLI
// arguments and passing them to functions within magellan's internal API.
//
// Each CLI subcommand will have at least one corresponding internal file
// with an API routine that implements the command's functionality. The main
// API routine will usually be the first function defined in the fill.
//
// For example:
//
//	cmd/scan.go    --> internal/scan.go ( magellan.ScanForAssets() )
//	cmd/collect.go --> internal/collect.go ( magellan.CollectAll() )
//	cmd/list.go    --> none (doesn't have API call since it's simple)
//	cmd/update.go  --> internal/update.go ( magellan.UpdateFirmware() )
package cmd

import (
	"fmt"
	"net"
	"os"
	"os/user"

	magellan "github.com/davidallendj/magellan/internal"
	"github.com/davidallendj/magellan/internal/util"
	"github.com/davidallendj/magellan/pkg/bmc"
	"github.com/davidallendj/magellan/pkg/secrets"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	FORMAT_LIST = "list"
	FORMAT_JSON = "json"
	FORMAT_YAML = "yaml"
)

// CLI arguments as variables to not fiddle with error-prone strings
var (
	currentUser     *user.User
	accessToken     string
	accessTokenPath string
	timeout         int
	concurrency     int
	ports           []int
	protocol        string
	cacertPath      string
	username        string
	password        string
	cachePath       string
	outputPath      string
	outputDir       string
	configPath      string
	verbose         bool
	debug           bool
	forceUpdate     bool
	insecure        bool
)

// The `root` command doesn't do anything on it's own except display
// a help message and then exits.
var rootCmd = &cobra.Command{
	Use: "magellan",
	Example: `  // a typical dynamic work flow with unknown hosts
  magellan scan --subnet 172.16.0.0/24
  magellan collect -v -F yaml -o nodes.yaml -u admin -p password123
  $EDITOR nodes.yaml
  magellan send -F yaml -d@nodes.yaml https://api.example.com
  magellan collect -v | magellan send 

  // show information in list
  magellan list -F yaml
  magellan list drives https://172.21.0.2:5000 -i -u admin -p password123

  // performing a crawl with known hosts
  magellan crawl https://172.16.0.100 -u admin -p password123 -i -F yaml -o nodes.yaml

  // manage secrets with secret store
  export MASTER_KEY=(magellan secrets generatekey)
  magellan secrets store https://172.16.0.100 root:password123
  magellan secrets list
  magellan secrets retrieve https://172.16.0.100
  magellan secrets remove https://172.16.0.100

  // manage sessions with session authentication (can be used with secret store)
  magellan sessions login https://172.16.0.100 -u root -p password123
  magellan sessions list
  magellan sessions delete --session-id $SESSION_ID --session-token $SESSION_TOKEN

  // manage cache with cache editting
  magellan cache new /tmp/magellan/$USER/assets.db
  magellan cache add https://172.16.0.100 443 tcp
  magellan cache remove https://172.16.0.100
  magellan cache list
  magellan cache info

  // manage cache interactively with editor
  magellan cache new ./my/new/cache.db
  magellan cache edit -i --cache ./my/new/cache.db
`,
	Short: "Redfish-based BMC discovery tool",
	Long:  "Redfish-based BMC discovery tool with dynamic discovery features.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				log.Error().Err(err).Msg("failed to print help")
			}
			os.Exit(0)
		}
	},
}

// This Execute() function is called from main to run the CLI.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(InitializeConfig)
	rootCmd.PersistentFlags().IntVarP(&concurrency, "concurrency", "j", -1, "Set the number of concurrent processes")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 5, "Set the timeout for requests in seconds")
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Set the config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Set to enable/disable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Set to enable/disable debug messages")
	rootCmd.PersistentFlags().StringVar(&accessToken, "access-token", "", "Set the access token")
	rootCmd.PersistentFlags().StringVar(&cachePath, "cache", fmt.Sprintf("/tmp/%s/magellan/assets.db", util.GetCurrentUsername()), "Set the scanning result cache path")

	// bind viper config flags with cobra
	checkBindFlagError(viper.BindPFlag("concurrency", rootCmd.PersistentFlags().Lookup("concurrency")))
	checkBindFlagError(viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout")))
	checkBindFlagError(viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")))
	checkBindFlagError(viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug")))
	checkBindFlagError(viper.BindPFlag("access-token", rootCmd.PersistentFlags().Lookup("verbose")))
	checkBindFlagError(viper.BindPFlag("cache", rootCmd.PersistentFlags().Lookup("cache")))
}

func checkBindFlagError(err error) {
	if err != nil {
		log.Error().Err(err).Msg("failed to bind cobra/viper flag")
	}
}

// InitializeConfig() initializes a new config object by loading it
// from a file given a non-empty string.
//
// See the 'LoadConfig' function in 'internal/config' for details.
func InitializeConfig() {
	if configPath != "" {
		err := magellan.LoadConfig(configPath)
		if err != nil {
			log.Error().Err(err).Msg("failed to load config")
		}
	}
}

// SetDefaults() resets all of the viper properties back to their
// default values.
//
// TODO: This function should probably be moved to 'internal/config.go'
// instead of in this file.
func SetDefaults() {
	viper.SetDefault("threads", 1)
	viper.SetDefault("timeout", 5)
	viper.SetDefault("config", "")
	viper.SetDefault("verbose", false)
	viper.SetDefault("debug", false)
	viper.SetDefault("cache", fmt.Sprintf("/tmp/%s/magellan/assets.db", util.GetCurrentUsername()))
	viper.SetDefault("scan.hosts", []string{})
	viper.SetDefault("scan.ports", []int{})
	viper.SetDefault("scan.subnets", []string{})
	viper.SetDefault("scan.subnet-masks", []net.IP{})
	viper.SetDefault("scan.disable-probing", false)
	viper.SetDefault("scan.disable-cache", false)
	viper.SetDefault("collect.username", "")
	viper.SetDefault("collect.password", "")
	viper.SetDefault("collect.protocol", "tcp")
	viper.SetDefault("collect.output", "/tmp/magellan/data/")
	viper.SetDefault("collect.force-update", false)
	viper.SetDefault("collect.cacert", "")
	viper.SetDefault("update.username", "")
	viper.SetDefault("update.password", "")
	viper.SetDefault("update.transfer-protocol", "https")
	viper.SetDefault("update.protocol", "tcp")
	viper.SetDefault("update.firmware.url", "")
	viper.SetDefault("update.firmware.version", "")
	viper.SetDefault("update.component", "")
	viper.SetDefault("update.status", false)

}

func initSecretsStore(uri string) secrets.SecretStore {
	var (
		store secrets.SecretStore
		err   error
	)
	if username != "" && password != "" {
		// First, try and load credentials from --username and --password if both are set.
		log.Debug().Str("id", uri).Msgf("--username and --password specified, using them for BMC credentials")
		store = secrets.NewStaticStore(username, password)
	} else {
		// Alternatively, locate specific credentials (falling back to default) and override those
		// with --username or --password if either are passed.
		log.Debug().Str("id", uri).Msgf("one or both of --username and --password NOT passed, attempting to obtain missing credentials from secret store at %s", secretsFile)
		if store, err = secrets.OpenStore(secretsFile); err != nil {
			log.Error().Str("id", uri).Err(err).Msg("failed to open local secrets store")
		}

		// Either none of the flags were passed or only one of them were; get
		// credentials from secrets store to fill in the gaps.
		bmcCreds, _ := bmc.GetBMCCredentials(store, uri)
		nodeCreds := secrets.StaticStore{
			Username: bmcCreds.Username,
			Password: bmcCreds.Password,
		}

		// If either of the flags were passed, override the fetched
		// credentials with them.
		if username != "" {
			log.Info().Str("id", uri).Msg("--username was set, overriding username for this BMC")
			nodeCreds.Username = username
		}
		if password != "" {
			log.Info().Str("id", uri).Msg("--password was set, overriding password for this BMC")
			nodeCreds.Password = password
		}

		store = &nodeCreds
	}
	return store
}

func validSecretArgs(masterKey string, secretsFile string) bool {
	return masterKey != "" && secretsFile != ""
}
