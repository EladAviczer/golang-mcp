package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

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

type SyncInput struct {
	App            string `json:"app"`                      // required
	Revision       string `json:"revision,omitempty"`       // branch/tag/SHA
	Prune          bool   `json:"prune,omitempty"`          // delete resources not in Git
	DryRun         bool   `json:"dryRun,omitempty"`         // simulate only
	Force          bool   `json:"force,omitempty"`          // force hooks/replace
	Wait           bool   `json:"wait,omitempty"`           // poll until done
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"` // default 300
}

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

func main() {
	host := flag.String("host", getenvDefault("MCP_HOST", "0.0.0.0"), "host to listen on")
	port := flag.Int("port", getenvIntDefault("MCP_PORT", 3000), "port to listen on")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "argocd-mini",
		Version: "1.1.0",
	}, nil)

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

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

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
