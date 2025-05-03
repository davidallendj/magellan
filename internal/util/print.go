package util

import (
	"encoding/json"
	"fmt"

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
	fmt.Printf("%s\n", string(b))
}
