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
    LOG_LEVEL=${LOG_LEVEL:-"error"}

    FALLBACK_DNS_ENABLED=${FALLBACK_DNS_ENABLED:-"false"}
    FALLBACK_DNS_SERVER=${FALLBACK_DNS_SERVER:-"1.1.1.1"}

    # Ports
    DOT_PORT=${DOT_PORT:-853}
    DOH_PORT=${DOH_PORT:-443}
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


# ------------------------------------------------------------------------------
# Multiplexed Port 443 Configuration (DoH + Admin UI)
# ------------------------------------------------------------------------------
INTERNAL_DOH_PORT="5553"
ADMIN_BACKEND_PORT="8080"

bashio::log.info "🌍 Unifying DoH and Admin UI on Port ${DOH_PORT} (multiplexed via Nginx)..."

# Setup Nginx
mkdir -p /run/nginx /etc/nginx/http.d

# Nginx Config: Terminates TLS, Multiplexes DNS and Admin UI
cat <<EOF >/etc/nginx/http.d/default.conf
server {
    listen ${DOH_PORT} ssl;
    http2 on;
    server_name _;

    ssl_certificate ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};
    ssl_protocols TLSv1.2 TLSv1.3;

    # Logs
    error_log /dev/stderr info;
    access_log /dev/stdout;

    # 1. Proxy DoH to CoreDNS (Internal Loopback HTTPS)
    location /dns-query {
        proxy_pass https://127.0.0.1:${INTERNAL_DOH_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_ssl_verify off;
    }

    # 2. Proxy everything else to Admin Backend (API & Dashboard)
    location / {
        proxy_pass http://127.0.0.1:${ADMIN_BACKEND_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Start Nginx in background
nginx &
NGINX_PID=$!
bashio::log.info "   Nginx multiplexer started (PID ${NGINX_PID})"

# CoreDNS port must match the internal proxy target
ACTUAL_COREDNS_PORT="${INTERNAL_DOH_PORT}"

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
tls://.:$DOT_PORT {
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

# ------------------------------------------------------------------------------
# ShieldDNS Admin & CoreDNS Execution
# ------------------------------------------------------------------------------

# Ensure config directories exist
mkdir -p /etc/shielddns /var/www/admin

echo "🚀 Starting ShieldDNS Services..."

# Export cert paths for the admin backend
export CERT_FILE
export KEY_FILE

# Start Admin Backend (Sidecar)
# The admin app generates /etc/Corefile based on its own config
/usr/bin/shielddns-admin &
ADMIN_PID=$!

# Initial Corefile if it doesn't exist
if [ ! -f "$COREFILE_PATH" ]; then
    echo ".:53 {
    bind 0.0.0.0
    forward . $ACTIVE_DNS_SERVER
    hosts /etc/shielddns/blocklist.hosts {
        reload 5s
        fallthrough
    }
    log
    errors
}" > $COREFILE_PATH
fi

# Start CoreDNS in background to pipe logs to stats processor (if we had one)
# For now, we just start it and let it log to stdout
/usr/bin/coredns -conf $COREFILE_PATH &
DNS_PID=$!

# Wait for ANY process to exit
PIDS="$DNS_PID $ADMIN_PID"
wait -n $PIDS

echo "❌ One of the processes exited. Shutting down..."
kill $PIDS 2>/dev/null
exit 1
