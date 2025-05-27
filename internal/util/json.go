package util

import (
	"encoding/json"
	"fmt"
	"strings"
)

type JSONObject = map[string]any
type JSONArray = []any

func TidyJSON(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "  ", "")
	return strings.ReplaceAll(s, "\"", "'")
}

func UpdateJSON(input []byte, key string, value JSONObject) ([]byte, error) {
	var (
		data   map[string]any
		output []byte
		err    error
	)

	if json.Valid(input) {
		// unmarshal input
		err = json.Unmarshal(input, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal input data: %v", err)
		}

		// add KV, marshal, and return
		data[key] = value
		output, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal updated data: %v", err)
		}
		return output, nil
	} else {
		return nil, fmt.Errorf("not valid json")
	}
}

func FromJSON(input []byte) (JSONObject, error) {
	if json.Valid(input) {
		var (
			obj JSONObject
			err error
		)
		err = json.Unmarshal(input, &obj)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal input data: %v", err)
		}
		return obj, nil
	} else {
		return nil, fmt.Errorf("not a valid JSON")
	}
}
