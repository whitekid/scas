package helper

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

func WriteJSONToFile(name string, data interface{}) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return WriteJSON(f, data)
}

func WriteJSON(w io.Writer, data interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func ReadJSONFile(name string, data interface{}) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return ReadJSON(f, data)
}

func ReadJSON(r io.Reader, data interface{}) error { return json.NewDecoder(r).Decode(data) }

func MarshalJSON(data interface{}) string {
	if data == nil {
		return ""
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		return ""
	}

	return buf.String()
}
