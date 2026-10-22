# Stage 1: Get CoreDNS binary
FROM coredns/coredns:1.15.0@sha256:0a9d8c8ddf34347eb59aad9a8784f0710de88d6d112726d11d271f9bc6daca26 AS binary

# Stage 2: Build Admin UI Backend
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS admin-build
ARG TARGETARCH
WORKDIR /app
COPY admin/ .
RUN go mod download && go mod tidy
RUN GOOS=linux GOARCH=$TARGETARCH go build -o shielddns-admin .

# Stage 3: Runtime Image
FROM alpine:3.24@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35

# Install dependencies including libcap for setcap
RUN apk add --no-cache jq ca-certificates bash curl dos2unix openssl libcap su-exec

# Create shielddns user and group with fixed IDs for easier volume permissions
RUN addgroup -g 1000 -S shielddns && adduser -u 1000 -S shielddns -G shielddns

# Create required directories and ensure correct ownership for non-root user
RUN mkdir -p /etc/shielddns /ssl /data && \
    chown -R shielddns:shielddns /etc/shielddns /ssl /data

RUN ln -s /ssl /certs

# Copy CoreDNS binary
COPY --from=binary /coredns /usr/bin/coredns

# Copy Admin binary (contains embedded web assets)
COPY --from=admin-build /app/shielddns-admin /usr/bin/shielddns-admin

# Grant capability to bind to privileged ports (53, 443, 853) to the binaries
RUN setcap 'cap_net_bind_service=+ep' /usr/bin/coredns && \
    setcap 'cap_net_bind_service=+ep' /usr/bin/shielddns-admin

# Expose ports
EXPOSE 53/udp 53/tcp 443/tcp 853/tcp

# Define persistent volumes
VOLUME ["/etc/shielddns", "/ssl"]

# Copy official presets lists for local fallback
COPY official/ /official/
RUN chown -R shielddns:shielddns /official

# Copy the entrypoint script
COPY run.sh /run.sh
RUN dos2unix /run.sh && chmod +x /run.sh && chown shielddns:shielddns /run.sh

# Switch to non-root user (initially root to fix volume permissions)
# USER shielddns

# The entrypoint will explicitly call bash to avoid shebang issues
ENTRYPOINT ["/bin/bash", "/run.sh"]
