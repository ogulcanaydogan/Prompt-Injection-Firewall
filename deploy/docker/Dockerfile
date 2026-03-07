FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pif-firewall ./cmd/firewall/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pif-cli ./cmd/pif-cli/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pif-webhook ./cmd/webhook/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /pif-firewall /usr/local/bin/pif-firewall
COPY --from=builder /pif-cli /usr/local/bin/pif-cli
COPY --from=builder /pif-webhook /usr/local/bin/pif-webhook
COPY rules/ /etc/pif/rules/
COPY config.yaml /etc/pif/config.yaml

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/pif-firewall"]
CMD ["proxy", "--config", "/etc/pif/config.yaml"]
