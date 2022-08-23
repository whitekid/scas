package helper

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func WriteYAMLToFile(name string, data interface{}) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return WriteYAML(f, data)
}

func WriteYAML(w io.Writer, data interface{}) error { return yaml.NewEncoder(w).Encode(data) }

func ReadYAMLFile(name string, data interface{}) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return ReadYAML(f, data)
}

func ReadYAML(r io.Reader, data interface{}) error { return yaml.NewDecoder(r).Decode(data) }
