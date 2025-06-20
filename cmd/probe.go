package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/davidallendj/magellan/pkg/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var probeCmd = &cobra.Command{
	Use: "probe [hosts...]",
	Example: ` // probe for Redfish service
  magellan probe https://172.16.0.100 https://172.16.0.101
`,
	Args:  cobra.MinimumNArgs(1),
	Short: "Probe specified URI for Redfish service.",
	Run: func(cmd *cobra.Command, args []string) {
		for _, host := range args {
			res, _, err := client.MakeRequest(
				nil,
				fmt.Sprintf("%s/redfish/v1/", host),
				http.MethodGet,
				nil,
				nil,
			)
			if err != nil {
				log.Error().Err(err).
					Str("host", host).Send()
				continue
			}
			if res.StatusCode == http.StatusOK {
				log.Info().Msg("found Redfish service")
				os.Exit(0)
			} else {
				log.Error().
					Int("status_code", res.StatusCode).
					Msg("something went wrong")
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(probeCmd)
}
