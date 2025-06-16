package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/davidallendj/magellan/internal/cache"
	"github.com/davidallendj/magellan/internal/cache/sqlite"
	"github.com/davidallendj/magellan/internal/util"
	magellan "github.com/davidallendj/magellan/pkg"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cacheOutputFormat string
	interactive       bool
	withHosts         []string
	withPorts         []int
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage found assets in cache.",
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

var cacheEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Modify cache data either interactively or non-interactively.",
	Run: func(cmd *cobra.Command, args []string) {
		// start the interactive editor
		if interactive {
			p := tea.NewProgram(cache.NewModel())
			if _, err := p.Run(); err != nil {
				fmt.Printf("failed to start the cache editor: %v", err)
				os.Exit(1)
			}
		} else {
			// only edit data with arguments
		}
	},
}

var cacheInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show cache-related information.",
	Run: func(cmd *cobra.Command, args []string) {
		printCacheInfo(cacheOutputFormat)
	},
}

func init() {
	// remove
	cacheRemoveCmd.Flags().StringSliceVar(&withHosts, "with-hosts", []string{}, "Remove all assets with specified hosts")
	cacheRemoveCmd.Flags().IntSliceVar(&withPorts, "with-ports", []int{}, "Remove all assets with specified ports")

	// edit
	cacheEditCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Edit cache data using interactive editor")

	cacheInfoCmd.Flags().StringVarP(&cacheOutputFormat, "format", "F", FORMAT_LIST, "Set the output format (list|json|yaml)")

	// commands
	cacheCmd.AddCommand(cacheRemoveCmd, cacheEditCmd, cacheInfoCmd)
	rootCmd.AddCommand(cacheCmd)
}

func printCacheInfo(format string) {
	assets, err := sqlite.GetScannedAssets(cachePath)
	if err != nil {
		log.Error().Err(err).Str("path", cachePath).Msg("failed to get assets to print cache info")
	}
	cacheData := map[string]any{
		"path":   cachePath,
		"assets": len(assets),
	}
	util.PrintMapWithFormat(cacheData, format)
}
