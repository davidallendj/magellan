package cmd

import (
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
	listOutputFormat string
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
			magellan.PrintMapFormat(map[string]any{
				"path": cachePath,
			}, format)
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
	ListCmd.Flags().StringVarP(&listOutputFormat, "format", "F", FORMAT_LIST, "Set the output format (json|yaml|table)")
	ListCmd.Flags().BoolVar(&showCache, "cache-info", false, "Show cache information and exit")
	rootCmd.AddCommand(ListCmd)
}
