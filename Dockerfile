# Stage 1: Get CoreDNS binary
FROM coredns/coredns:1.14.2 AS binary

# Stage 2: Build Admin UI Backend
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS admin-build
ARG TARGETARCH
WORKDIR /app
COPY admin/ .
RUN go mod download && go mod tidy
RUN GOOS=linux GOARCH=$TARGETARCH go build -o shielddns-admin main.go

# Stage 3: Runtime Image
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache jq ca-certificates bash curl nginx dos2unix

# Create web root and required directories
RUN mkdir -p /var/www/html /run/nginx

# Copy Web Assets
COPY admin/www /var/www/admin
COPY logo.png /var/www/admin/logo.png

# Copy CoreDNS binary
COPY --from=binary /coredns /usr/bin/coredns

# Copy Admin binary
COPY --from=admin-build /app/shielddns-admin /usr/bin/shielddns-admin

# Expose ports
EXPOSE 53/udp 53/tcp 443/tcp 853/tcp

# Copy the entrypoint script
COPY run.sh /run.sh
RUN dos2unix /run.sh && chmod +x /run.sh

# The entrypoint will explicitly call bash to avoid shebang issues
ENTRYPOINT ["/bin/bash", "/run.sh"]
