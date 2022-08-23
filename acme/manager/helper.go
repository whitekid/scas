package manager

import "strings"

func idFromURI(l string) string {
	parts := strings.Split(l, "/")
	if len(parts) == 0 {
		return ""
	}

	return parts[len(parts)-1]
}
