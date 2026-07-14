# AERO Edge Server Docker 镜像（多阶段构建，<15MB）
#
# 用法:
#   docker build -t aero/edge -f deploy/Dockerfile .
#   docker run -d --name aero-edge \
#     -p 443:443 -p 8443:8443 -p 80:80 \
#     -e AERO_TOKEN=my-secret-token \
#     -e AERO_DOMAIN=edge.myhost.com \
#     -e AERO_EMAIL=admin@myhost.com \
#     aero/edge:latest

# 阶段 1: 编译
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.work go.work.sum ./
COPY aero-edge/go.mod aero-edge/go.sum ./aero-edge/
COPY proto/ ./proto/
RUN cd aero-edge && go mod download
COPY aero-edge/ ./aero-edge/
RUN cd aero-edge && CGO_ENABLED=0 go build -ldflags="-s -w" -o /aero-edge ./cmd/aero-edge/

# 阶段 2: 运行（最小镜像）
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /aero-edge /usr/local/bin/aero-edge
EXPOSE 443 8443 80
ENV AERO_TOKEN=""
ENV AERO_DOMAIN=""
ENV AERO_EMAIL=""
ENV AERO_PORTS="443,8443,80"
ENV AERO_SNI="cdn-aero.com"
ENV AERO_LOG_FORMAT="json"
ENTRYPOINT ["/usr/local/bin/aero-edge"]
CMD ["-token", "${AERO_TOKEN}", "-autocert", "${AERO_DOMAIN}", \
     "-autocert-email", "${AERO_EMAIL}", "-ports", "${AERO_PORTS}", \
     "-sni", "${AERO_SNI}", "-log-format", "${AERO_LOG_FORMAT}"]
