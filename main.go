package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AppItem struct {
	Name          string `json:"name"`
	Project       string `json:"project"`
	Sync          string `json:"sync"`
	Health        string `json:"health"`
	Repo          string `json:"repo"`
	DestServer    string `json:"destServer"`
	DestNamespace string `json:"destNamespace"`
}

type ListAppsOutput struct {
	Applications []AppItem `json:"applications"`
}

type ListImagesOutput struct {
	AppName string   `json:"name"`
	Images  []string `json:"images"`
}

func ArgoListApps(ctx context.Context, req *mcp.CallToolRequest, _ *struct{}) (*mcp.CallToolResult, any, error) {
	// Read environment configuration
	serverURL := os.Getenv("ARGOCD_SERVER_URL")
	token := os.Getenv("ARGOCD_TOKEN")
	insecure := os.Getenv("ARGOCD_INSECURE_SKIP_VERIFY") == "true"

	if serverURL == "" || token == "" {
		return nil, nil, fmt.Errorf("missing required env vars: ARGOCD_SERVER_URL and ARGOCD_TOKEN")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ARGOCD_SERVER_URL: %w", err)
	}
	u.Path = "/api/v1/applications"

	// Configure HTTP client (allow skipping TLS for labs)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	// Prepare request
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	reqHTTP.Header.Set("Authorization", "Bearer "+token)
	reqHTTP.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("argo CD API returned %d", resp.StatusCode)
	}

	// Decode minimal response
	var body struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Project string `json:"project"`
				Source  struct {
					RepoURL string `json:"repoURL"`
				} `json:"source"`
				Destination struct {
					Server    string `json:"server"`
					Namespace string `json:"namespace"`
				} `json:"destination"`
			} `json:"spec"`
			Status struct {
				Sync   struct{ Status string } `json:"sync"`
				Health struct{ Status string } `json:"health"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Map to output struct
	out := ListAppsOutput{Applications: make([]AppItem, 0, len(body.Items))}
	for _, it := range body.Items {
		out.Applications = append(out.Applications, AppItem{
			Name:          it.Metadata.Name,
			Project:       it.Spec.Project,
			Sync:          it.Status.Sync.Status,
			Health:        it.Status.Health.Status,
			Repo:          it.Spec.Source.RepoURL,
			DestServer:    it.Spec.Destination.Server,
			DestNamespace: it.Spec.Destination.Namespace,
		})
	}

	// Return as MCP content (JSON string for maximum compatibility)
	payload, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(payload)},
		},
	}, nil, nil
}

func ListIamges(ctx context.Context, req *mcp.CallToolRequest, _ *struct{}) (*mcp.CallToolResult, any, error) {
	serverURL := os.Getenv("ARGOCD_SERVER_URL")
	token := os.Getenv("ARGOCD_TOKEN")
	insecure := os.Getenv("ARGOCD_INSECURE_SKIP_VERIFY") == "true"
	if serverURL == "" || token == "" {
		return nil, nil, fmt.Errorf("missing required env vars: ARGOCD_SERVER_URL and ARGOCD_TOKEN")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ARGOCD_SERVER_URL: %w", err)
	}
	u.Path = "/api/v1/applications"
	// Configure HTTP client (allow skipping TLS for labs)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	// Prepare request
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	reqHTTP.Header.Set("Authorization", "Bearer "+token)
	reqHTTP.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("argo CD API returned %d", resp.StatusCode)
	}

	var body struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Summary struct {
					Images []string `json:"images"`
				} `json:"summary"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("failed to decode response: %w", err)
	}
	out := make([]ListImagesOutput, 0, len(body.Items))
	for _, it := range body.Items {
		out = append(out, ListImagesOutput{
			AppName: it.Metadata.Name,
			Images:  it.Status.Summary.Images,
		})
	}

	payload, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(payload)},
		},
	}, nil, nil
}

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func main() {
	// Use flags like the SDK example; also support env overrides for K8s
	host := flag.String("host", getenvDefault("MCP_HOST", "0.0.0.0"), "host to listen on")
	port := flag.Int("port", getenvIntDefault("MCP_PORT", 3000), "port to listen on")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Create an MCP server.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "argocd-mini",
		Version: "1.0.0",
	}, nil)

	// Register tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "argo_list_apps",
		Description: "List Argo CD applications using environment configuration",
	}, ArgoListApps)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "argo_list_images",
		Description: "List deployed images per application using environment configuration",
	}, ListIamges)
	// Create the streamable HTTP handler (same API as your time example)
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	// Optionally add a simple health endpoint (useful for probes)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("MCP server listening on http://%s/mcp", addr)
	log.Printf("ARGOCD_SERVER_URL=%s INSECURE=%v",
		os.Getenv("ARGOCD_SERVER_URL"), os.Getenv("ARGOCD_INSECURE_SKIP_VERIFY"))

	if err := http.ListenAndServe(addr, loggingHandler(mux)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

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
