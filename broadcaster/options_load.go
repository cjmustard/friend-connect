package broadcaster

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadOptions(path string) (Options, error) {
	file, err := os.Open(path)
	if err != nil {
		return Options{}, fmt.Errorf("open options: %w", err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()

	var opts Options
	if err := dec.Decode(&opts); err != nil {
		return Options{}, fmt.Errorf("decode options: %w", err)
	}
	opts.ApplyDefaults()
	return opts, nil
}

func MustLoadOptions(path string) Options {
	opts, err := LoadOptions(path)
	if err != nil {
		panic(err)
	}
	return opts
}
