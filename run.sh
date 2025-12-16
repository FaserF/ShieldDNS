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

else
    echo "ℹ️  Standard Docker environment detected."
    UPSTREAM_DNS=${UPSTREAM_DNS:-$DEFAULT_UPSTREAM}
    CERT_FILE=${CERT_FILE:-$DEFAULT_CERT}
    KEY_FILE=${KEY_FILE:-$DEFAULT_KEY}
    TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}
    LOG_LEVEL=${LOG_LEVEL:-"error"}
fi

echo "🔧 Configuration:"
echo "   Upstream: $UPSTREAM_DNS"
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


# Generate Corefile
echo "📝 Generating Corefile..."
cat <<EOF > $COREFILE_PATH
tls://.:853 {
    tls $CERT_FILE $KEY_FILE
    forward . $UPSTREAM_DNS
    $(echo -e "$DNS_LOG_CONFIG")
}

https://.:443 https://.:784 https://.:2443 {
    tls $CERT_FILE $KEY_FILE
    forward . $UPSTREAM_DNS
    $(echo -e "$DNS_LOG_CONFIG")
}
EOF

# Start CoreDNS
echo "🚀 Starting CoreDNS..."
# Exec CoreDNS.
# NOTE: If we started cloudflared in background, exec replaces the shell, so CoreDNS becomes PID 1 (or child of).
# However, if cloudflared crashes, the container might stay alive but tunnel down.
# Ideally we should monitor both. But for simplicity in this script, we exec CoreDNS.
# Check if tunnel is backgrounded
if [ -n "$TUNNEL_PID" ]; then
    # We cannot use exec because we want to keep checking tunnel?
    # Actually, standard Docker practice: main process is the one we want.
    # If DNS dies, container dies. If Tunnel dies, we might want container to die too?
    # Let's keep it simple: Exec CoreDNS. If Tunnel dies, user will see logs (if forwarded).
    # But ideally use a supervisor like s6. Since we don't have s6, we just rely on happy path.
    /usr/bin/coredns -conf $COREFILE_PATH &
    DNS_PID=$!

    # Wait for any process to exit
    wait -n $DNS_PID $TUNNEL_PID

    # If we are here, one of them exited.
    echo "❌ One of the processes exited. Shutting down..."
    kill $DNS_PID 2>/dev/null
    kill $TUNNEL_PID 2>/dev/null
    exit 1
else
    # No tunnel, just exec
    exec /usr/bin/coredns -conf $COREFILE_PATH
fi
