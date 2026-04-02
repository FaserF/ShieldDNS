# Stage 1: Get CoreDNS binary
FROM coredns/coredns:1.14.2@sha256:e7e6440cfd1e919280958f5b5a6ab2b184d385bba774c12ad2a9e1e4183f90d9 AS binary

# Stage 2: Build Admin UI Backend
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS admin-build
ARG TARGETARCH
WORKDIR /app
COPY admin/ .
RUN go mod download && go mod tidy
RUN GOOS=linux GOARCH=$TARGETARCH go build -o shielddns-admin .

# Stage 3: Runtime Image
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

# Install dependencies
RUN apk add --no-cache jq ca-certificates bash curl nginx dos2unix openssl

# Create web root and required directories
RUN mkdir -p /var/www/html /run/nginx /ssl
RUN ln -s /ssl /certs

# Copy Web Assets
COPY admin/www /var/www/admin
COPY www/logo.png /var/www/admin/logo.png
COPY www/favicon.ico /var/www/admin/favicon.ico
# Copy CoreDNS binary
COPY --from=binary /coredns /usr/bin/coredns

# Copy Admin binary
COPY --from=admin-build /app/shielddns-admin /usr/bin/shielddns-admin

# Expose ports
EXPOSE 53/udp 53/tcp 443/tcp 853/tcp

# Define persistent volumes
VOLUME ["/etc/shielddns", "/ssl"]

# Copy the entrypoint script
COPY run.sh /run.sh
RUN dos2unix /run.sh && chmod +x /run.sh

# The entrypoint will explicitly call bash to avoid shebang issues
ENTRYPOINT ["/bin/bash", "/run.sh"]
