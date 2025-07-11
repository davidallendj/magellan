package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/araddon/dateparse"
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
	timestampf        string
	timestamp         time.Time
	cacheOutputFormat string
	interactive       bool
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage assets (new, add, remove, edit, etc.) in cache.",
}

var cacheNewCmd = &cobra.Command{
	Use: "new",
	Example: `  // create a new cache database
  magellan cache new ./path/to/new_cache.db
	`,
	Short: "Create a new cache at specified path.",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var cacheAddCmd = &cobra.Command{
	Use: "add [host] [port] [protocol] <timestamp>",
	Example: `  // create a new entry in cache
  magellan cache add https://172.16.0.105 443,5000 tcp "06/25/2025"

  // create new entry with no timestamp specified with specific cache
  magellan cache add https://172.16.0.111 443 tcp --cache ./assets.db
	`,
	Short: "Add an entry to the specified cache.",
	Args:  cobra.RangeArgs(3, 4),
	Run: func(cmd *cobra.Command, args []string) {
		// set positional args to vars
		host = args[0]
		protocol = args[2]

		// convert ports
		for _, portStr := range strings.Split(args[1], ",") {
			port, err := strconv.ParseInt(portStr, 10, 16)
			if err != nil {
				log.Error().Err(err).Msg("failed to convert port value")
				continue
			}
			ports = append(ports, int(port))
		}

		// parse timestamp
		if len(args) == 4 {
			var err error
			timestamp, err = dateparse.ParseAny(args[3])
			if err != nil {
				log.Error().Err(err).Msg("failed to parse time arg")
				os.Exit(1)
			}
		} else {
			log.Warn().Msg("time not specified...using current time")
			timestamp = time.Now()
		}

		for _, port := range ports {
			// create a new entry in cache using flag arguments
			err := sqlite.InsertRemoteAssets(cachePath, magellan.RemoteAsset{
				Host:      host,
				Port:      port,
				Protocol:  protocol,
				Timestamp: timestamp,
			})
			if err != nil {
				log.Error().Err(err).
					Str("path", cachePath).
					Str("host", host).
					Msg("failed to insert asset into cache")
			}
		}

	},
}

var cacheRemoveCmd = &cobra.Command{
	Use: "remove [hosts...]",
	Example: `  // remove an entry in cache
  magellan cache remove https://172.16.0.113
	`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Remove hosts from cache.",
	Run: func(cmd *cobra.Command, args []string) {
		err := sqlite.DeleteRemoteAssetsByHost(cachePath, args...)
		if err != nil {
			log.Error().Err(err).Str("path", cachePath).Msg("failed to delete assets in cache")
		}

	},
}

var cacheEditCmd = &cobra.Command{
	Use: "edit",
	Example: `  // star the cache editor
  magellan cache edit -i

  // edit a single entry only changing values specified (e.g. port and protocol)
  magellan cache edit https://172.16.0.101 --port 443 --protocol udp

  // edit two entries' time stamps
  magellan cache edit https://172.16.0.101 https://172.16.0.102 --timestamp 06/25/2025
	`,
	Args: func(cmd *cobra.Command, args []string) error {
		if interactive {
			// must have no args if interactive
			if err := cobra.ExactArgs(0)(cmd, args); err != nil {
				return err
			}
		} else {
			// must have at least one arg if not interactive
			if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
				return err
			}
		}
		return nil
	},
	Short: "Edit existing cache data.",
	Run: func(cmd *cobra.Command, args []string) {
		var (
			columns []table.Column
			rows    []table.Row
			styles  table.Styles
		)

		if interactive {
			// load the assets found from scan
			scannedResults, err := sqlite.GetRemoteAssets(cachePath)
			if err != nil {
				log.Error().Err(err).Str("path", cachePath).Msg("failed to get scanned assets from cache")
			}

			// set columns to cache headers
			columns = []table.Column{
				{Title: "host", Width: 30},
				{Title: "ports", Width: 8},
				{Title: "protocol", Width: 10},
				{Title: "timestamp", Width: 20},
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

			// create a new table
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

			m := cache.NewModel(cachePath, &assetsTable)
			if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
				fmt.Println("Error running program:", err)
				os.Exit(1)
			}
		} else {
			// non-interactive editting
			for _, host := range args {
				// get the asset from cache for host
				asset, err := sqlite.GetRemoteAsset(cachePath, host)
				if err != nil {
					log.Warn().Err(err).
						Str("host", host).
						Str("path", cachePath).
						Msg("failed to get asset from cache")
					continue
				}
				if asset == nil {
					log.Warn().Err(err).
						Str("host", host).
						Str("path", cachePath).
						Msg("found asset is not valid")
					continue
				}

				// only modify values that are set
				if host != "" {
					asset.Host = host
				}
				if protocol != "" {
					asset.Protocol = protocol
				}
				if timestampf != "" {
					newTimestamp, err := dateparse.ParseAny(timestampf)
					if err != nil {
						log.Error().Err(err).Msg("failed to parse timestamp value")
					} else {
						asset.Timestamp = newTimestamp
					}
				}

				// reinsert the asset into cache for each port
				for _, port := range ports {
					newAsset := *asset
					newAsset.Port = port
					err = sqlite.DeleteRemoteAssetsByHost(cachePath, host)
					if err != nil {
						log.Error().Err(err).
							Str("host", host).
							Str("path", cachePath).
							Msg("failed to delete asset in cache")
						continue
					}
					err = sqlite.InsertRemoteAssets(cachePath, newAsset)
					if err != nil {
						log.Error().Err(err).
							Str("host", host).
							Str("path", cachePath).
							Msg("failed to re-insert asset into cache")
					}
				}

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
	cacheEditCmd.Flags().StringVar(&host, "host", "", "Set the new host value.")
	cacheEditCmd.Flags().IntSliceVar(&ports, "port", nil, "Set the new port values as comma-separated list.")
	cacheEditCmd.Flags().StringVar(&scheme, "scheme", "https", "Set the new scheme value. (default is 'https')")
	cacheEditCmd.Flags().StringVar(&protocol, "protocol", "tcp", "Set the new protocol value. (default is 'tcp')")
	cacheEditCmd.Flags().StringVar(&timestampf, "timestamp", "", "Set the new timestamp value.")
	cacheEditCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Start an interactive TUI to edit cache data")

	cacheInfoCmd.Flags().StringVarP(&cacheOutputFormat, "format", "F", FORMAT_LIST, "Set the output format (list|json|yaml)")

	cacheCmd.AddCommand(
		cacheNewCmd,
		cacheAddCmd,
		cacheRemoveCmd,
		cacheEditCmd,
		cacheInfoCmd,
		ListCmd, // magellan cache list (alias for 'magellan list')
	)
	rootCmd.AddCommand(cacheCmd)
}

func printCacheInfo(format string) {
	assets, err := sqlite.GetRemoteAssets(cachePath)
	if err != nil {
		log.Error().Err(err).Str("path", cachePath).Msg("failed to get assets to print cache info")
	}
	cacheData := map[string]any{
		"path":   cachePath,
		"assets": len(assets),
	}
	util.PrintMapWithFormat(cacheData, format)
}
