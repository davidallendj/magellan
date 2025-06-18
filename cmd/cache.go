package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	cache "github.com/davidallendj/magellan/internal/cache"
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
	Use: "edit",
	Example: `  magellan cache edit
  magellan cache edit --host https://172.16.0.101 --port 443 --protocol udp
  magellan cache edit --host https://172.16.0.101
	`,
	Args:  cobra.ExactArgs(0),
	Short: "Edit existing cache data.",
	Run: func(cmd *cobra.Command, args []string) {
		var (
			columns []table.Column
			rows    []table.Row
			styles  table.Styles
		)

		if interactive {
			// load the assets found from scan
			scannedResults, err := sqlite.GetScannedAssets(cachePath)
			if err != nil {
				log.Error().Err(err).Str("path", cachePath).Msg("failed to get scanned assets from cache")
			}

			// set columns to cache headers
			columns = []table.Column{
				{Title: "hosts", Width: 20},
				{Title: "ports", Width: 5},
				{Title: "protocol", Width: 8},
				{Title: "timestamp", Width: 12},
			}

			// set rows to cache data
			for _, asset := range scannedResults {
				rows = append(rows, table.Row{
					asset.Host,
					fmt.Sprintf("%d", asset.Port),
					asset.Protocol,
					fmt.Sprintf("%d", asset.Timestamp.Unix()),
				})
			}

			// new table
			assetsTable := table.New(
				table.WithColumns(columns),
				table.WithRows(rows),
				table.WithFocused(true),
				table.WithHeight(10),
			)

			// set up table styling
			styles = table.DefaultStyles()
			styles.Header = styles.Header.
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				BorderBottom(true).
				Bold(false)
			styles.Selected = styles.Selected.
				Foreground(lipgloss.Color("229")).
				Background(lipgloss.Color("57")).
				Bold(false)
			assetsTable.SetStyles(styles)

			m := cache.Model{Table: assetsTable}
			if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
				fmt.Println("Error running program:", err)
				os.Exit(1)
			}
		}
	},
}

var cacheInfoCmd = &cobra.Command{
	Use:     "info",
	Short:   "Show cache-related information and exit.",
	Example: `  magellan cache info`,
	Run: func(cmd *cobra.Command, args []string) {
		printCacheInfo(cacheOutputFormat)
	},
}

func init() {
	// remove
	cacheRemoveCmd.Flags().StringSliceVar(&withHosts, "with-hosts", []string{}, "Remove all assets with specified hosts")
	cacheRemoveCmd.Flags().IntSliceVar(&withPorts, "with-ports", []int{}, "Remove all assets with specified ports")

	cacheEditCmd.Flags().IntSliceVar(&ports, "port", nil, "Adds additional ports to scan for each host with unspecified ports.")
	cacheEditCmd.Flags().StringVar(&scheme, "scheme", "https", "Set the default scheme to use if not specified in host URI. (default is 'https')")
	cacheEditCmd.Flags().StringVar(&protocol, "protocol", "tcp", "Set the default protocol to use in scan. (default is 'tcp')")
	cacheEditCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Start an interactive TUI to edit cache data")

	cacheInfoCmd.Flags().StringVarP(&cacheOutputFormat, "format", "F", FORMAT_LIST, "Set the output format (list|json|yaml)")

	cacheCmd.AddCommand(
		cacheRemoveCmd,
		cacheInfoCmd,
		cacheEditCmd,
		ListCmd,
	)
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
