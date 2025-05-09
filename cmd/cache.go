package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/davidallendj/magellan/internal/cache/sqlite"
	magellan "github.com/davidallendj/magellan/pkg"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	withHosts []string
	withPorts []int
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage found assets in cache.",
	Run: func(cmd *cobra.Command, args []string) {
		// show the help for cache and exit
		if len(args) <= 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

var cacheRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a host from a scanned cache list.",
	Run: func(cmd *cobra.Command, args []string) {
		assets := []magellan.RemoteAsset{}

		// add all assets directly from positional args
		for _, arg := range args {
			var (
				port int
				uri  *url.URL
				err  error
			)
			uri, err = url.ParseRequestURI(arg)
			if err != nil {
				log.Error().Err(err).Msg("failed to parse arg")
			}

			// convert port to its "proper" type
			if uri.Port() == "" {
				uri.Host += ":443"
			}
			port, err = strconv.Atoi(uri.Port())
			if err != nil {
				log.Error().Err(err).Msg("failed to convert port to integer type")
			}
			asset := magellan.RemoteAsset{
				Host: fmt.Sprintf("%s://%s", uri.Scheme, uri.Hostname()),
				Port: port,
			}
			assets = append(assets, asset)
		}

		// Add all assets with specified hosts (same host different different ports)
		// This should produce the following SQL:
		// DELETE FROM magellan_scanned_assets WHERE host=:host
		for _, host := range withHosts {
			assets = append(assets, magellan.RemoteAsset{
				Host: host,
				Port: -1,
			})
		}
		// Add all assets with specified ports (same port different hosts)
		// This should produce the following SQL:
		// DELETE FROM magellan_scanned_assets WHERE port=:port
		for _, port := range withPorts {
			assets = append(assets, magellan.RemoteAsset{
				Host: "",
				Port: port,
			})
		}
		if len(assets) <= 0 {
			log.Error().Msg("nothing to do")
			os.Exit(1)
		}
		sqlite.DeleteScannedAssets(cachePath, assets...)
	},
}

func init() {
	cacheRemoveCmd.Flags().StringSliceVar(&withHosts, "with-hosts", []string{}, "Remove all assets with specified hosts")
	cacheRemoveCmd.Flags().IntSliceVar(&withPorts, "with-ports", []int{}, "Remove all assets with specified ports")
	cacheCmd.AddCommand(cacheRemoveCmd)
	rootCmd.AddCommand(cacheCmd)
}
