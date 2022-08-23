package helper

import (
	"io"
	"net/http"
)

func HttpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func MustHttpGet(url string) []byte {
	data, err := HttpGet(url)
	if err != nil {
		panic(err)
	}
	return data
}
