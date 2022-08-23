package helper

import (
	"io"
	"os"

	"github.com/whitekid/goxp/log"
)

// ReadFile read data from file or stdin
func ReadFile(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(os.Stdin)
	}

	log.Debugf("read file %s", name)
	return os.ReadFile(name)
}

func MustReadFile(name string) []byte {
	data, err := ReadFile(name)
	if err != nil {
		panic(err)
	}

	return data
}

// WriteFile write data to file or stdout
func WriteFile(name string, data []byte, perm os.FileMode) error {
	if name == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(name, data, perm)
}

func MustWriteFile(name string, data []byte, perm os.FileMode) {
	if err := WriteFile(name, data, perm); err != nil {
		panic(err)
	}
}
