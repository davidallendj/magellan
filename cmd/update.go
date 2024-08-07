package cmd

import (
	magellan "github.com/OpenCHAMI/magellan/internal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	host             string
	port             int
	firmwareUrl      string
	firmwareVersion  string
	component        string
	transferProtocol string
	status           bool
)

// The `update` command provides an interface to easily update firmware
// using Redfish. It also provides a simple way to check the status of
// an update in-progress.
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update BMC node firmware",
	Long: "Perform an firmware update using Redfish by providing a remote firmware URL and component.\n" +
		"Examples:\n" +
		"  magellan update --bmc.host 172.16.0.108 --bmc.port 443 --username bmc_username --password bmc_password --firmware-url http://172.16.0.200:8005/firmware/bios/image.RBU --component BIOS\n" +
		"  magellan update --status --bmc.host 172.16.0.108 --bmc.port 443 --username bmc_username --password bmc_password",
	Run: func(cmd *cobra.Command, args []string) {
		// check if required params are set
		if host == "" || username == "" || password == "" {
			log.Error().Msg("requires host, user, and pass to be set")
		}

		// get status if flag is set and exit
		if status {
			err := magellan.GetUpdateStatus(&magellan.UpdateParams{
				FirmwarePath:     firmwareUrl,
				FirmwareVersion:  firmwareVersion,
				Component:        component,
				TransferProtocol: transferProtocol,
				CollectParams: magellan.CollectParams{
					Host:     host,
					Username: username,
					Password: password,
					Timeout:  timeout,
					Port:     port,
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
			TransferProtocol: transferProtocol,
			CollectParams: magellan.CollectParams{
				Host:     host,
				Username: username,
				Password: password,
				Timeout:  timeout,
				Port:     port,
			},
		})
		if err != nil {
			log.Error().Err(err).Msgf("failed to update firmware")
		}
	},
}

func init() {
	updateCmd.Flags().StringVar(&host, "bmc.host", "", "set the BMC host")
	updateCmd.Flags().IntVar(&port, "bmc.port", 443, "set the BMC port")
	updateCmd.Flags().StringVar(&username, "username", "", "set the BMC user")
	updateCmd.Flags().StringVar(&password, "password", "", "set the BMC password")
	updateCmd.Flags().StringVar(&transferProtocol, "transfer-protocol", "HTTP", "set the transfer protocol")
	updateCmd.Flags().StringVar(&firmwareUrl, "firmware.url", "", "set the path to the firmware")
	updateCmd.Flags().StringVar(&firmwareVersion, "firmware.version", "", "set the version of firmware to be installed")
	updateCmd.Flags().StringVar(&component, "component", "", "set the component to upgrade")
	updateCmd.Flags().BoolVar(&status, "status", false, "get the status of the update")

	viper.BindPFlag("update.bmc.host", updateCmd.Flags().Lookup("bmc.host"))
	viper.BindPFlag("update.bmc.port", updateCmd.Flags().Lookup("bmc.port"))
	viper.BindPFlag("update.username", updateCmd.Flags().Lookup("username"))
	viper.BindPFlag("update.password", updateCmd.Flags().Lookup("password"))
	viper.BindPFlag("update.transfer-protocol", updateCmd.Flags().Lookup("transfer-protocol"))
	viper.BindPFlag("update.protocol", updateCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("update.firmware.url", updateCmd.Flags().Lookup("firmware.url"))
	viper.BindPFlag("update.firmware.version", updateCmd.Flags().Lookup("firmware.version"))
	viper.BindPFlag("update.component", updateCmd.Flags().Lookup("component"))
	viper.BindPFlag("update.secure-tls", updateCmd.Flags().Lookup("secure-tls"))
	viper.BindPFlag("update.status", updateCmd.Flags().Lookup("status"))

	rootCmd.AddCommand(updateCmd)
}
