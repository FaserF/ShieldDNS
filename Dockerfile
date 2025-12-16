# Stage 1: Get CoreDNS binary
FROM coredns/coredns:latest AS binary

# Stage 2: Get Cloudflare Tunnel binary
FROM cloudflare/cloudflared:latest AS tunnel

# Stage 3: Runtime Image
FROM alpine:latest

# Install dependencies
# jq: needed for parsing HA Addon options
# bind-tools: gives us 'dig'/'kdig'
# ca-certificates: needed for TLS
# libc6-compat: needed for cloudflared on Alpine
RUN apk add --no-cache jq ca-certificates bash curl libc6-compat nginx

# Create web root and required directories
RUN mkdir -p /var/www/html /run/nginx

# Copy Web Assets
COPY www/index.html /var/www/html/index.html
COPY logo.png /var/www/html/logo.png

# Copy CoreDNS binary
COPY --from=binary /coredns /usr/bin/coredns

# Copy Cloudflared binary
COPY --from=tunnel /usr/local/bin/cloudflared /usr/bin/cloudflared

# Expose DoT port
EXPOSE 853

# Copy the entrypoint script
COPY run.sh /run.sh
RUN chmod +x /run.sh

# The entrypoint will generate the Corefile based on env vars
ENTRYPOINT ["/run.sh"]
