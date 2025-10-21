# ---- Build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build statically linked binary for small final image
RUN CGO_ENABLED=0 GOOS=linux go build -o server .

# ---- Final stage ----
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/server /app/server

# Environment vars expected at runtime (safe defaults)
ENV ARGOCD_SERVER_URL=""
ENV ARGOCD_TOKEN=""
ENV ARGOCD_INSECURE_SKIP_VERIFY="false"

EXPOSE 3000
# Run as non-root user (distroless nonroot UID 65532)
USER 65532

ENTRYPOINT ["/app/server"]
