#!/bin/bash

# Define paths
OPTIONS_PATH="/data/options.json"
COREFILE_PATH="/Corefile"

# Default values
DEFAULT_UPSTREAM="1.1.1.1"
DEFAULT_CERT="/ssl/fullchain.pem"
DEFAULT_KEY="/ssl/privkey.pem"

echo "➡️  Starting ShieldDNS Initialization..."

# Check if running as Home Assistant Addon
if [ -f "$OPTIONS_PATH" ]; then
    echo "ℹ️  Home Assistant Addon environment detected."

    # helper function to read from json
    function read_option {
        jq -r ".$1 // empty" $OPTIONS_PATH
    }

    UPSTREAM_DNS=$(read_option "upstream_dns")
    CERT_FILE=$(read_option "certfile")
    KEY_FILE=$(read_option "keyfile")
    TUNNEL_TOKEN=$(read_option "cloudflare_tunnel_token")
    LOG_LEVEL=$(read_option "log_level")

    # Fallback if specific keys are missing in json but file exists (unlikely if schema is good)
    [ -z "$UPSTREAM_DNS" ] && UPSTREAM_DNS=$DEFAULT_UPSTREAM
    [ -z "$CERT_FILE" ] && CERT_FILE=$DEFAULT_CERT
    [ -z "$KEY_FILE" ] && KEY_FILE=$DEFAULT_KEY

    # Prepend /ssl/ to cert paths if they are just filenames (common in HA)
    if [[ "$CERT_FILE" != /* ]]; then CERT_FILE="/ssl/$CERT_FILE"; fi
    if [[ "$KEY_FILE" != /* ]]; then KEY_FILE="/ssl/$KEY_FILE"; fi

    FALLBACK_DNS_ENABLED=$(read_option "fallback_dns")
    FALLBACK_DNS_SERVER=$(read_option "fallback_dns_server")

else
    echo "ℹ️  Standard Docker environment detected."
    UPSTREAM_DNS=${UPSTREAM_DNS:-$DEFAULT_UPSTREAM}
    CERT_FILE=${CERT_FILE:-$DEFAULT_CERT}
    KEY_FILE=${KEY_FILE:-$DEFAULT_KEY}
    TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}
    LOG_LEVEL=${LOG_LEVEL:-"error"}

    FALLBACK_DNS_ENABLED=${FALLBACK_DNS_ENABLED:-"false"}
    FALLBACK_DNS_SERVER=${FALLBACK_DNS_SERVER:-"1.1.1.1"}
fi

# Default fallback server if not set
[ -z "$FALLBACK_DNS_SERVER" ] && FALLBACK_DNS_SERVER="1.1.1.1"

# Check Reachability and Fallback Logic
ACTIVE_DNS_SERVER="$UPSTREAM_DNS"
DNS_MODE="Main"

if [ "$FALLBACK_DNS_ENABLED" == "true" ]; then
    echo "🔍 Checking availability of Upstream DNS: $UPSTREAM_DNS"

    # Simple check using ping (assuming ICMP allowed) or nc if available.
    # Since this is a DNS container, we might not have nc/ping.
    # Let's assume we can use timeout + bash /dev/tcp or just see if we can resolve/connect
    # but technically Upstream is often an IP.
    # We will try a simple ping with small timeout.

    if ping -c 1 -W 2 "$UPSTREAM_DNS" &> /dev/null; then
         echo "✅ Upstream DNS ($UPSTREAM_DNS) is reachable."
    else
         echo "⚠️  Upstream DNS ($UPSTREAM_DNS) is NOT reachable!"
         echo "🔄 Switching to Fallback DNS: $FALLBACK_DNS_SERVER"
         ACTIVE_DNS_SERVER="$FALLBACK_DNS_SERVER"
         DNS_MODE="Fallback"
    fi
else
    echo "ℹ️  Fallback DNS is disabled. Using configured Upstream: $UPSTREAM_DNS"
fi

echo "🔧 Configuration:"
echo "   Upstream: $ACTIVE_DNS_SERVER ($DNS_MODE)"
echo "   Cert:     $CERT_FILE"
echo "   Key:      $KEY_FILE"
if [ -n "$TUNNEL_TOKEN" ]; then
    echo "   Tunnel:   Enabled (Token provided)"
else
    echo "   Tunnel:   Disabled"
fi
echo "   Log Lvl:  $LOG_LEVEL"


# Validation mechanism
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "⚠️  WARNING: Certificates not found at specified paths!"
    echo "   Running in non-TLS mode might fail or server might not start if TLS block is active."
fi

# Write Status for Info Page
mkdir -p /var/www/html
cat <<EOF > /var/www/html/status.json
{
  "status": "online",
  "mode": "$DNS_MODE",
  "upstream": "$ACTIVE_DNS_SERVER",
  "checked_at": "$(date)"
}
EOF

# Determine Logging Configuration for CoreDNS
# CoreDNS plugins: errors (always), log (query log), debug (packet/trace)
DNS_LOG_CONFIG="errors"
if [ "$LOG_LEVEL" == "info" ] || [ "$LOG_LEVEL" == "debug" ]; then
    DNS_LOG_CONFIG="$DNS_LOG_CONFIG\n    log"
fi
if [ "$LOG_LEVEL" == "debug" ]; then
    DNS_LOG_CONFIG="$DNS_LOG_CONFIG\n    debug"
fi


# Start Cloudflare Tunnel if Token is present
if [ -n "$TUNNEL_TOKEN" ]; then
    echo "🚇 Starting Cloudflare Tunnel..."
    # Determine tunnel log level
    TUNNEL_LOG="info"
    if [ "$LOG_LEVEL" == "debug" ]; then TUNNEL_LOG="debug"; fi
    if [ "$LOG_LEVEL" == "error" ]; then TUNNEL_LOG="error"; fi

    cloudflared tunnel run --token "$TUNNEL_TOKEN" --loglevel "$TUNNEL_LOG" &
    TUNNEL_PID=$!
    echo "   Tunnel started with PID $TUNNEL_PID"
fi



# Start Optional Web Server
ENABLE_INFO_PAGE=${ENABLE_INFO_PAGE:-"false"}
WEB_PORT=${WEB_PORT:-8080}

if [ "$ENABLE_INFO_PAGE" == "true" ]; then
    echo "🌍 Starting Web Server (Info Page) on port $WEB_PORT..."

    # Configure Nginx (Minimal)
    # Ensure PID dir exists
    mkdir -p /run/nginx

    cat <<EOF > /etc/nginx/http.d/default.conf
server {
    listen $WEB_PORT;
    root /var/www/html;
    index index.html;
    server_name _;

    # Logs to stdout/stderr
    error_log /dev/stderr info;
    access_log /dev/stdout;
}
EOF

    # Start Nginx in background
    nginx &
    NGINX_PID=$!
    echo "   Web Server started with PID $NGINX_PID"
fi

# Generate Corefile
echo "📝 Generating Corefile..."

# Validation
if [ -z "$DOT_PORT" ] && [ -z "$DOH_PORT" ]; then
    echo "❌ CRITICAL: Neither DOT_PORT nor DOH_PORT is set!"
    exit 1
fi

# Clear file
> $COREFILE_PATH

if [ -n "$DOT_PORT" ]; then
cat <<EOF >> $COREFILE_PATH
tls://.:853 {
    tls $CERT_FILE $KEY_FILE
    forward . $ACTIVE_DNS_SERVER
    $(echo -e "$DNS_LOG_CONFIG")
}
EOF
fi

if [ -n "$DOH_PORT" ]; then
cat <<EOF >> $COREFILE_PATH
https://.:$ACTUAL_COREDNS_PORT {
    tls $CERT_FILE $KEY_FILE
    forward . $ACTIVE_DNS_SERVER
    $(echo -e "$DNS_LOG_CONFIG")
}
EOF
fi

# Start CoreDNS
echo "🚀 Starting CoreDNS..."
# Exec CoreDNS.
# NOTE: If we started cloudflared in background, exec replaces the shell, so CoreDNS becomes PID 1 (or child of).
# However, if cloudflared crashes, the container might stay alive but tunnel down.
# Ideally we should monitor both. But for simplicity in this script, we exec CoreDNS.
# Check if tunnel is backgrounded
# Check if we have background processes to monitor (Tunnel or Nginx)
if [ -n "$TUNNEL_PID" ] || [ -n "$NGINX_PID" ]; then

    # Start CoreDNS in background so we can wait on all PIDs
    /usr/bin/coredns -conf $COREFILE_PATH &
    DNS_PID=$!

    # Wait for ANY process to exit
    # Construct list of PIDs
    PIDS="$DNS_PID $TUNNEL_PID $NGINX_PID"

    wait -n $PIDS

    # If we are here, one of them exited.
    echo "❌ One of the processes exited. Shutting down..."
    # Kill all
    kill $DNS_PID $TUNNEL_PID $NGINX_PID 2>/dev/null
    exit 1
else
    # No background services, just exec CoreDNS directly
    exec /usr/bin/coredns -conf $COREFILE_PATH
fi
