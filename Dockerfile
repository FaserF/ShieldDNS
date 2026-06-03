# Stage 1: Get CoreDNS binary
FROM coredns/coredns:1.14.3@sha256:b21d26b915e10acb5bc78715c1e8b6047ab2675389b2bcc18b3a6499d90e74c0 AS binary

# Stage 2: Build Admin UI Backend
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS admin-build
ARG TARGETARCH
WORKDIR /app
COPY admin/ .
RUN go mod download && go mod tidy
RUN GOOS=linux GOARCH=$TARGETARCH go build -o shielddns-admin .

# Stage 3: Runtime Image
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

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

# Copy the entrypoint script
COPY run.sh /run.sh
RUN dos2unix /run.sh && chmod +x /run.sh && chown shielddns:shielddns /run.sh

# Switch to non-root user (initially root to fix volume permissions)
# USER shielddns

# The entrypoint will explicitly call bash to avoid shebang issues
ENTRYPOINT ["/bin/bash", "/run.sh"]
