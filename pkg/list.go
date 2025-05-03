package magellan

import (
	"fmt"
	"strings"
	"time"

	"github.com/davidallendj/magellan/internal/util"
	"github.com/davidallendj/magellan/pkg/crawler"
	"github.com/rs/zerolog/log"
	"github.com/stmcginnis/gofish"
	"github.com/stmcginnis/gofish/redfish"
)

func PrintRemoteAssets(data []RemoteAsset, format string) {
	switch strings.ToLower(format) {
	case "json":
		util.PrintJSON(data)
	case "yaml":
		util.PrintYAML(data)
	case "none":
		for _, r := range data {
			fmt.Printf("%s:%d (%s) @%s\n", r.Host, r.Port, r.Protocol, r.Timestamp.Format(time.UnixDate))
		}
	default:
		log.Error().Msg("unrecognized format")
	}
}

func PrintMapFormat(data map[string]any, format string) {
	switch strings.ToLower(format) {
	case "json":
		util.PrintJSON(data)
	case "yaml":
		util.PrintYAML(data)
	case "none":
		for k, v := range data {
			fmt.Printf("%s: %v\n", k, v)
		}
	default:
		log.Error().Msg("unrecognized format")
	}
}

func ListDrives(cc *crawler.CrawlerConfig) ([]*redfish.Drive, error) {
	user, err := cc.GetUserPass()
	if err != nil {
		return nil, fmt.Errorf("failed to get username and password: %v", err)
	}
	log.Info().Str("username", user.Username).Str("password", user.Password).Str("host", cc.URI).Msg("credentials used")
	// Create a new instance of gofish client, ignoring self-signed certs
	c, err := gofish.Connect(gofish.ClientConfig{
		Endpoint:  cc.URI,
		Username:  user.Username,
		Password:  user.Password,
		Insecure:  cc.Insecure,
		BasicAuth: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to host: %v", util.TidyJSON(err.Error()))
	}
	defer c.Logout()

	// Retrieve the service root
	systems, err := c.Service.Systems()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve systems: %v", err)
	}

	// aggregate all of the drives together
	foundDrives := []*redfish.Drive{}
	for _, system := range systems {
		storage, err := system.Storage()
		if err != nil {
			continue
		}

		for _, ss := range storage {
			drives, err := ss.Drives()
			if err != nil {
				continue
			}

			foundDrives = append(foundDrives, drives...)
		}
	}
	return foundDrives, nil
}

func PrintDrives(drives []*redfish.Drive) {
	for i, drive := range drives {
		fmt.Printf("Drive %d\n", i)
		fmt.Printf("\tManufacturer: %s\n", drive.Manufacturer)
		fmt.Printf("\tModel: %s\n", drive.Model)
		fmt.Printf("\tSize: %d GiB\n", (drive.CapacityBytes / 1024 / 1024 / 1024))
		fmt.Printf("\tSerial number: %s\n", drive.SerialNumber)
		fmt.Printf("\tPart number: %s\n", drive.PartNumber)
		fmt.Printf("\tLocation: %s %d\n", drive.PhysicalLocation.PartLocation.LocationType, drive.PhysicalLocation.PartLocation.LocationOrdinalValue)
	}
}
