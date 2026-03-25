# Stage 1: Get CoreDNS binary
FROM coredns/coredns:1.14.2 AS binary

# Stage 2: Build Admin UI Backend
FROM golang:1.24-alpine AS admin-build
WORKDIR /app
COPY admin/ .
RUN go build -o shielddns-admin main.go

# Stage 3: Runtime Image
FROM alpine:latest

# Install dependencies
# jq: needed for parsing HA Addon options
# bind-tools: gives us 'dig'/'kdig'
# ca-certificates: needed for TLS
RUN apk add --no-cache jq ca-certificates bash curl nginx

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
EXPOSE 53/udp 53/tcp 8080/tcp

# Copy the entrypoint script
COPY run.sh /run.sh
RUN chmod +x /run.sh

# The entrypoint will generate the Corefile based on env vars
ENTRYPOINT ["/run.sh"]
