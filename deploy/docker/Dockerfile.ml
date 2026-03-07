# ML-enabled PIF build with ONNX Runtime support
# Requires CGO_ENABLED=1 and ONNX Runtime shared libraries
#
# Build:
#   docker build -f deploy/docker/Dockerfile.ml -t pif:ml .
#
# Run:
#   docker run -p 8080:8080 \
#     -e PIF_DETECTOR_ML_MODEL_PATH=/models \
#     -v ./ml/output/onnx/quantized:/models \
#     pif:ml

FROM golang:1.25 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime shared libraries
ARG ONNX_VERSION=1.16.3
RUN wget -q https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && tar -xzf onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && cp onnxruntime-linux-x64-${ONNX_VERSION}/lib/* /usr/local/lib/ \
    && cp -r onnxruntime-linux-x64-${ONNX_VERSION}/include/* /usr/local/include/ \
    && ldconfig \
    && rm -rf onnxruntime-linux-x64-${ONNX_VERSION}*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with ML tag and CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -tags ml -ldflags="-s -w" -o /pif-firewall ./cmd/firewall/
RUN CGO_ENABLED=1 GOOS=linux go build -tags ml -ldflags="-s -w" -o /pif-cli ./cmd/pif-cli/
RUN CGO_ENABLED=1 GOOS=linux go build -tags ml -ldflags="-s -w" -o /pif-webhook ./cmd/webhook/

# Runtime image: debian slim (needed for shared libraries)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r pif && useradd -r -g pif pif

# Copy ONNX Runtime libraries from builder
COPY --from=builder /usr/local/lib/libonnxruntime* /usr/local/lib/
RUN ldconfig

# Copy PIF binaries and config
COPY --from=builder /pif-firewall /usr/local/bin/pif-firewall
COPY --from=builder /pif-cli /usr/local/bin/pif-cli
COPY --from=builder /pif-webhook /usr/local/bin/pif-webhook
COPY rules/ /etc/pif/rules/
COPY config.yaml /etc/pif/config.yaml

# Model directory — mount your ONNX model here
RUN mkdir -p /models && chown pif:pif /models
VOLUME /models

EXPOSE 8080

USER pif:pif

ENTRYPOINT ["/usr/local/bin/pif-firewall"]
CMD ["proxy", "--config", "/etc/pif/config.yaml"]
