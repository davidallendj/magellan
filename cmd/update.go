package cmd

import (
	"os"
	"strings"

	magellan "github.com/davidallendj/magellan/internal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	host             string
	firmwareUrl      string
	firmwareVersion  string
	component        string
	transferProtocol string
	showStatus       bool
)

// The `update` command provides an interface to easily update firmware
// using Redfish. It also provides a simple way to check the status of
// an update in-progress.
var UpdateCmd = &cobra.Command{
	Use:   "update hosts...",
	Short: "Update BMC node firmware",
	Long: "Perform an firmware update using Redfish by providing a remote firmware URL and component.\n\n" +
		"Examples:\n" +
		"  magellan update 172.16.0.108:443 --username bmc_username --password bmc_password --firmware-url http://172.16.0.200:8005/firmware/bios/image.RBU --component BIOS\n" +
		"  magellan update 172.16.0.108:443 --status --username bmc_username --password bmc_password",
	Run: func(cmd *cobra.Command, args []string) {
		// check that we have at least one host
		if len(args) <= 0 {
			log.Error().Msg("update requires at least one host")
			os.Exit(1)
		}

		// get status if flag is set and exit
		for _, arg := range args {
			if showStatus {
				err := magellan.GetUpdateStatus(&magellan.UpdateParams{
					FirmwarePath:     firmwareUrl,
					FirmwareVersion:  firmwareVersion,
					Component:        component,
					TransferProtocol: transferProtocol,
					CollectParams: magellan.CollectParams{
						URI:      arg,
						Username: username,
						Password: password,
						Timeout:  timeout,
					},
				})
				if err != nil {
					log.Error().Err(err).Msgf("failed to get update status")
				}
				return
			}

			// initiate a remote update
			err := magellan.UpdateFirmwareRemote(&magellan.UpdateParams{
				FirmwarePath:     firmwareUrl,
				FirmwareVersion:  firmwareVersion,
				Component:        component,
				TransferProtocol: strings.ToUpper(transferProtocol),
				CollectParams: magellan.CollectParams{
					URI:      host,
					Username: username,
					Password: password,
					Timeout:  timeout,
				},
			})
			if err != nil {
				log.Error().Err(err).Msgf("failed to update firmware")
			}
		}
	},
}

func init() {
	UpdateCmd.Flags().StringVar(&username, "username", "", "Set the BMC user")
	UpdateCmd.Flags().StringVar(&password, "password", "", "Set the BMC password")
	UpdateCmd.Flags().StringVar(&transferProtocol, "scheme", "https", "Set the transfer protocol")
	UpdateCmd.Flags().StringVar(&firmwareUrl, "firmware-url", "", "Set the path to the firmware")
	UpdateCmd.Flags().StringVar(&firmwareVersion, "firmware-version", "", "Set the version of firmware to be installed")
	UpdateCmd.Flags().StringVar(&component, "component", "", "Set the component to upgrade (BMC|BIOS)")
	UpdateCmd.Flags().BoolVar(&showStatus, "status", false, "Get the status of the update")

	checkBindFlagError(viper.BindPFlag("update.username", UpdateCmd.Flags().Lookup("username")))
	checkBindFlagError(viper.BindPFlag("update.password", UpdateCmd.Flags().Lookup("password")))
	checkBindFlagError(viper.BindPFlag("update.scheme", UpdateCmd.Flags().Lookup("scheme")))
	checkBindFlagError(viper.BindPFlag("update.firmware-url", UpdateCmd.Flags().Lookup("firmware-url")))
	checkBindFlagError(viper.BindPFlag("update.firmware-version", UpdateCmd.Flags().Lookup("firmware-version")))
	checkBindFlagError(viper.BindPFlag("update.component", UpdateCmd.Flags().Lookup("component")))
	checkBindFlagError(viper.BindPFlag("update.status", UpdateCmd.Flags().Lookup("status")))

	rootCmd.AddCommand(UpdateCmd)
}
