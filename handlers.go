package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
