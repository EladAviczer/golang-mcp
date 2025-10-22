package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvIntDefault(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var x int
		if _, err := fmt.Sscanf(v, "%d", &x); err == nil {
			return x
		}
	}
	return def
}

func newHTTPClient(insecure bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func setAuthBearer(h http.Header, token string) {
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		h.Set("Authorization", token)
	} else {
		h.Set("Authorization", "Bearer "+token)
	}
}

func readBodyMaxN(r io.Reader, n int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	return string(b)
}
