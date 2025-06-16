package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/davidallendj/magellan/internal/cache/sqlite"
	urlx "github.com/davidallendj/magellan/internal/urlx"
	magellan "github.com/davidallendj/magellan/pkg"
	"github.com/davidallendj/magellan/pkg/crawler"
	"github.com/davidallendj/magellan/pkg/secrets"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

var (
	showCache        bool
	showCacheInfo    bool
	listOutputFormat string
	listUsername     string
	listPassword     string
)

// The `list` command provides an easy way to show what was found
// and stored in a cache database from a scan. The data that's stored
// is what is consumed by the `collect` command with the --cache flag.
var ListCmd = &cobra.Command{
	Use: "list",
	Example: `  magellan list
  magellan list --cache ./assets.db
  magellan list --cache-info
	`,
	Args:  cobra.ExactArgs(0),
	Short: "List information stored in cache from a scan",
	Long: "Prints all of the host and associated data found from performing a scan.\n" +
		"See the 'scan' command on how to perform a scan.",
	Run: func(cmd *cobra.Command, args []string) {
		// check if we just want to show cache-related info and exit
		if showCacheInfo {
			printCacheInfo(listOutputFormat)
			os.Exit(0)
		}

		// load the assets found from scan
		scannedResults, err := sqlite.GetScannedAssets(cachePath)
		if err != nil {
			log.Error().Err(err).Str("path", cachePath).Msg("failed to get scanned assets from cache")
		}
		switch strings.ToLower(listOutputFormat) {
		case FORMAT_JSON:
			b, err := json.Marshal(scannedResults)
			if err != nil {
				log.Error().Err(err).Msgf("failed to unmarshal cached data to JSON")
			}
			fmt.Printf("%s\n", string(b))
		case FORMAT_YAML:
			b, err := yaml.Marshal(scannedResults)
			if err != nil {
				log.Error().Err(err).Msgf("failed to unmarshal cached data to YAML")
			}
			fmt.Printf("%s\n", string(b))
		case FORMAT_LIST:
			for _, r := range scannedResults {
				fmt.Printf("%s:%d (%s) @%s\n", r.Host, r.Port, r.Protocol, r.Timestamp.Format(time.UnixDate))
			}
		default:
			log.Error().Msg("unrecognized format")
			os.Exit(1)
		}

		// print cache data in specified format
		magellan.PrintRemoteAssets(scannedResults, listOutputFormat)
	},
}

var listDrivesCmd = &cobra.Command{
	Use: "drives [hosts...]",
	Example: `  # list all storage drives with username/password override and skip TLS verification
  magellan list drives https://$bmc_host -u $bmc_username -p $bmc_password -i

  # list all storage drives with secrets store defaults
  export MASTER_KEY=$(magellan secrets generatekey)
  magellan secrets store default $bmc_username:$bmc_password --secrets-file secrets/store.json
  magellan list drives https://$bmc_host --secrets-file secrets/store.json`,
	Args: func(cmd *cobra.Command, args []string) error {
		// Validate that the only argument is a valid URI
		var err error
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		args[0], err = urlx.Sanitize(args[0])
		if err != nil {
			return fmt.Errorf("failed to sanitize URI: %w", err)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		store := secrets.NewStaticStore(listUsername, listPassword)
		drives, err := magellan.ListDrives(&crawler.CrawlerConfig{
			URI:             args[0],
			CredentialStore: store, //initSecretsStore(args[0]),
			Insecure:        insecure,
			UseDefault:      false,
		})
		if err != nil {
			log.Error().Err(err).Msg("failed to get drives")
			os.Exit(1)
		}
		magellan.PrintDrives(drives)
	},
}

func init() {
	ListCmd.Flags().StringVarP(&listOutputFormat, "format", "F", "none", "Set the output format (list|json|yaml)")
	ListCmd.Flags().BoolVar(&showCacheInfo, "cache-info", false, "Alias for 'magellan cache info'")

	listDrivesCmd.Flags().StringVarP(&listUsername, "username", "u", "", "Set the username for BMC login")
	listDrivesCmd.Flags().StringVarP(&listPassword, "password", "p", "", "Set the password for BMC login")
	listDrivesCmd.Flags().BoolVarP(&insecure, "insecure", "i", false, "Skip TLS verification")
	listDrivesCmd.Flags().StringVarP(&secretsFile, "secrets-file", "f", "secrets.json", "Set the path to secrets store file to store credentials")

	ListCmd.AddCommand(listDrivesCmd)
	rootCmd.AddCommand(ListCmd)
}
