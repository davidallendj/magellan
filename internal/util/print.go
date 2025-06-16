package util

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

func PrintJSON(data any) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Error().Err(err).Msgf("failed to marshal scanned results to JSON")
	}
	fmt.Println(string(b))
}

func PrintYAML(data any) {
	b, err := yaml.Marshal(data)
	if err != nil {
		log.Error().Err(err).Msgf("failed to marshal scanned results to JSON")
	}
	fmt.Print(string(b))
}

func PrintMap(data map[string]any) {
	for k, v := range data {
		fmt.Printf("%s: %v\n", k, v)
	}
}

func PrintMapWithFormat(data map[string]any, format string) {
	switch strings.ToLower(format) {
	case "json":
		PrintJSON(data)
	case "yaml":
		PrintYAML(data)
	case "list":
		PrintMap(data)
	default:
		log.Error().Msg("PrintMapWithFormat: unrecognized format")
	}
}
