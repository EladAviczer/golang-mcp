# MCP - Demo
### Repo includes a full demo for MCP written in golang using the offical SDK.
#### Current tools:
- argo_list_apps
- argo_list_images
- argo_sync_app

### Environment variables for MPC deployment:
- ARGOCD_TOKEN (string)
- ARGOCD_SERVER_URL (string)
- ARGOCD_INSECURE_SKIP_VERIFY (bool)

---
- kubernetes deployment (cm and secret also) for the MCP Server is also provided.
- Kagent manifests includede: ModelConfig, RemoteMCPServer, Agent

---
For Docker compose deployment take a look at dockerr-compose.yaml (create relevant .env file)
``docker compose up``
