package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

/* =========================
   Types (response payloads)
   ========================= */

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

/* ================
   Sync tool inputs
   ================ */

type SyncInput struct {
	App            string `json:"app"`                      // required
	Revision       string `json:"revision,omitempty"`       // branch/tag/SHA
	Prune          bool   `json:"prune,omitempty"`          // delete resources not in Git
	DryRun         bool   `json:"dryRun,omitempty"`         // simulate only
	Force          bool   `json:"force,omitempty"`          // force hooks/replace
	Wait           bool   `json:"wait,omitempty"`           // poll until done
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"` // default 300
}

// Body sent to Argo CD /sync endpoint
type argoSyncRequest struct {
	Revision    string   `json:"revision,omitempty"`
	Prune       bool     `json:"prune,omitempty"`
	DryRun      bool     `json:"dryRun,omitempty"`
	SyncOptions []string `json:"syncOptions,omitempty"`
	Strategy    *struct {
		Hook *struct {
			Force bool `json:"force,omitempty"`
		} `json:"hook,omitempty"`
	} `json:"strategy,omitempty"`
}

/* ======================
   Shared HTTP utilities
   ====================== */

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

/* =====================
   Tools: Argo list apps
   ===================== */

func ArgoListApps(ctx context.Context, req *mcp.CallToolRequest, _ *struct{}) (*mcp.CallToolResult, any, error) {
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

	client := newHTTPClient(insecure)

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	setAuthBearer(reqHTTP.Header, token)
	reqHTTP.Header.Set("Accept", "application/json")

	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("argocd API returned %d: %s", resp.StatusCode, readBodyMaxN(resp.Body, 4<<10))
	}

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

	payload, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}},
	}, nil, nil
}

/* =======================
   Tools: Argo list images
   ======================= */

func ListImages(ctx context.Context, req *mcp.CallToolRequest, _ *struct{}) (*mcp.CallToolResult, any, error) {
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

	client := newHTTPClient(insecure)

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	setAuthBearer(reqHTTP.Header, token)
	reqHTTP.Header.Set("Accept", "application/json")

	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("argocd API returned %d: %s", resp.StatusCode, readBodyMaxN(resp.Body, 4<<10))
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
		Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}},
	}, nil, nil
}

/*
======================

	Tool: Argo sync (POST)
	======================
*/
func decodeToolArgs[T any](p *mcp.CallToolParamsRaw, out *T) error {
	if p == nil {
		// No params provided: leave out as zero value
		return nil
	}
	// Convert struct to []byte
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	// Try envelope with "arguments"
	var env struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Arguments) > 0 {
		return json.Unmarshal(env.Arguments, out)
	}
	// Fallback: treat the raw as the object directly
	return json.Unmarshal(raw, out)
}

func ArgoSyncApp(ctx context.Context, req *mcp.CallToolRequest, _ *struct{}) (*mcp.CallToolResult, any, error) {
	// Parse input
	var in SyncInput
	if err := decodeToolArgs(req.Params, &in); err != nil {
		return nil, nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.App == "" {
		return nil, nil, fmt.Errorf("missing input.app")
	}
	if in.TimeoutSeconds <= 0 {
		in.TimeoutSeconds = 300
	}

	// Env
	serverURL := os.Getenv("ARGOCD_SERVER_URL")
	token := os.Getenv("ARGOCD_TOKEN")
	insecure := os.Getenv("ARGOCD_INSECURE_SKIP_VERIFY") == "true"
	if serverURL == "" || token == "" {
		return nil, nil, fmt.Errorf("missing required env vars: ARGOCD_SERVER_URL and ARGOCD_TOKEN")
	}

	// Endpoint
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ARGOCD_SERVER_URL: %w", err)
	}
	u.Path = "/api/v1/applications/" + url.PathEscape(in.App) + "/sync"

	// Body
	body := argoSyncRequest{
		Revision: in.Revision,
		Prune:    in.Prune,
		DryRun:   in.DryRun,
	}
	if in.Force {
		body.Strategy = &struct {
			Hook *struct {
				Force bool `json:"force,omitempty"`
			} `json:"hook,omitempty"`
		}{
			Hook: &struct {
				Force bool `json:"force,omitempty"`
			}{Force: true},
		}
	}
	payload, _ := json.Marshal(&body)

	// POST
	client := newHTTPClient(insecure)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	setAuthBearer(httpReq.Header, token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("sync request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("sync http %d: %s", resp.StatusCode, readBodyMaxN(resp.Body, 4<<10))
	}

	// If not waiting, return early
	if !in.Wait {
		out := map[string]any{"app": in.App, "phase": "Requested"}
		js, _ := json.MarshalIndent(out, "", "  ")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(js)}}}, nil, nil
	}

	// Wait/poll until terminal phase or timeout
	ctxWait, cancel := context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()

	statusURL := *u
	statusURL.Path = "/api/v1/applications/" + url.PathEscape(in.App)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	type appStatus struct {
		Status struct {
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
			OperationState *struct {
				Phase      string `json:"phase"` // Succeeded|Failed|Error|Running|...
				Message    string `json:"message"`
				FinishedAt string `json:"finishedAt"`
			} `json:"operationState"`
			Sync struct {
				Status string `json:"status"` // Synced|OutOfSync
			} `json:"sync"`
		} `json:"status"`
	}

	for {
		select {
		case <-ctxWait.Done():
			out := map[string]any{
				"app":    in.App,
				"phase":  "Timeout",
				"reason": "wait exceeded",
			}
			js, _ := json.MarshalIndent(out, "", "  ")
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(js)}}}, nil, nil

		case <-ticker.C:
			getReq, _ := http.NewRequestWithContext(ctxWait, http.MethodGet, statusURL.String(), nil)
			setAuthBearer(getReq.Header, token)
			getReq.Header.Set("Accept", "application/json")

			r, err := client.Do(getReq)
			if err != nil {
				return nil, nil, fmt.Errorf("status request failed: %w", err)
			}
			defer r.Body.Close()

			if r.StatusCode < 200 || r.StatusCode >= 300 {
				return nil, nil, fmt.Errorf("status http %d: %s", r.StatusCode, readBodyMaxN(r.Body, 4<<10))
			}

			var st appStatus
			if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
				return nil, nil, fmt.Errorf("decode status: %w", err)
			}

			phase := "Unknown"
			msg := ""
			finished := ""
			if st.Status.OperationState != nil {
				phase = st.Status.OperationState.Phase
				msg = st.Status.OperationState.Message
				finished = st.Status.OperationState.FinishedAt
			}

			if phase == "Succeeded" || phase == "Failed" || phase == "Error" {
				out := map[string]any{
					"app":        in.App,
					"phase":      phase,
					"health":     st.Status.Health.Status,
					"syncStatus": st.Status.Sync.Status,
					"message":    msg,
					"finishedAt": finished,
				}
				js, _ := json.MarshalIndent(out, "", "  ")
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(js)}}}, nil, nil
			}
		}
	}
}

/* ============
   HTTP server
   ============ */

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
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

func main() {
	// Flags + env overrides
	host := flag.String("host", getenvDefault("MCP_HOST", "0.0.0.0"), "host to listen on")
	port := flag.Int("port", getenvIntDefault("MCP_PORT", 3000), "port to listen on")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// MCP server
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "argocd-mini",
		Version: "1.1.0",
	}, nil)

	// Register tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "argo_list_apps",
		Description: "List Argo CD applications using environment configuration",
	}, ArgoListApps)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "argo_list_images",
		Description: "List deployed images per application using environment configuration",
	}, ListImages)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "argo_sync_app",
		Description: "Sync an Argo CD application (POST /api/v1/applications/{name}/sync). Args: {app, revision?, prune?, dryRun?, force?, wait?, timeoutSeconds?}",
	}, ArgoSyncApp)

	// Streamable HTTP handler for MCP
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	// Mux + healthz
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
