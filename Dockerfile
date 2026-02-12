FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/telemetry-service .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/telemetry-service /app/telemetry-service
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Service config
ENV LISTEN_ADDR=":8080"
ENV MAX_BODY_BYTES="1024"
ENV RATE_LIMIT_RPM="60"
ENV RATE_BURST="20"
ENV UPSTREAM_TIMEOUT_MS="4000"
ENV ENABLE_REQUEST_LOGGING="false"

# Cache config
ENV ENABLE_CACHE="true"
ENV CACHE_TTL_SECONDS="300"
ENV ENABLE_REDIS="false"

# Alert config (optional)
ENV ALERT_ENABLED="false"
ENV ALERT_FAILURE_THRESHOLD="20.0"
ENV ALERT_CHECK_INTERVAL_MIN="15"
ENV ALERT_COOLDOWN_MIN="60"

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -q --spider http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
