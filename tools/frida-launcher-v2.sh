#!/system/bin/sh
# Stealth launcher for anti-detection frida-server
#
# Usage: sh frida-launcher-v2.sh <server-binary> [host_forward_port]
#   host_forward_port = adb forward local TCP port on PC (default 27100); ignored for binding in unix mode
#
# Default LISTEN_MODE=unix  ->  APP_LISTEN=unix:<random16>  (NOT in /proc/net/tcp)
# Legacy  LISTEN_MODE=tcp   ->  APP_LISTEN=127.0.0.1:<port>
#
# Runtime hiding:
#   - no "-l" in cmdline (APP_LISTEN env; needs server with APP_LISTEN support)
#   - unix mode: zero TCP listeners
#   - staging copy unlinked after exec -> /proc/PID/exe "(deleted)"
#   - delete source binary after copy
#   - main thread comm stays kworker/*; rename worker threads only

set -e

FRIDA_BIN="$1"
FORWARD_PORT="${2:-27100}"
DELETE_SOURCE="${DELETE_SOURCE:-1}"
LISTEN_MODE="${LISTEN_MODE:-unix}"
LISTEN_META="/data/local/tmp/.listen"

if [ "$(id -u)" != "0" ]; then
    exec su -c "sh \"$0\" \"$FRIDA_BIN\" \"$FORWARD_PORT\""
fi

if [ -z "$FRIDA_BIN" ]; then
    echo "Usage: $0 <server-binary> [host_forward_port]"
    exit 1
fi

if [ ! -f "$FRIDA_BIN" ]; then
    echo "[!] Binary not found: $FRIDA_BIN"
    exit 1
fi

rand_hex() {
    dd if=/dev/urandom bs=1 count="$1" 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

FAKE_NAME="kworker/$(rand_hex 2):$(rand_hex 1)"
RANDOM_BIN="/data/local/tmp/.$(rand_hex 8)"

cp "$FRIDA_BIN" "$RANDOM_BIN"
chmod 700 "$RANDOM_BIN"

if [ "$DELETE_SOURCE" = "1" ] && [ "$FRIDA_BIN" != "$RANDOM_BIN" ]; then
    rm -f "$FRIDA_BIN" 2>/dev/null || true
fi

case "$LISTEN_MODE" in
    unix)
        SOCKET_NAME="$(rand_hex 8)$(rand_hex 8)"
        LISTEN_ARG="unix:$SOCKET_NAME"
        ;;
    tcp)
        if [ "$FORWARD_PORT" = "0" ]; then
            FORWARD_PORT=$(($RANDOM % 50000 + 10000))
        fi
        LISTEN_ARG="127.0.0.1:$FORWARD_PORT"
        ;;
    *)
        echo "[!] Unknown LISTEN_MODE=$LISTEN_MODE (use unix or tcp)"
        exit 1
        ;;
esac

# Default off: keep "-l unix:..." out of /proc/PID/cmdline (server reads APP_LISTEN env).
USE_CMDLINE_LISTEN="${USE_CMDLINE_LISTEN:-0}"

{
    echo "mode=$LISTEN_MODE"
    echo "forward_port=$FORWARD_PORT"
    echo "app_listen=$LISTEN_ARG"
    [ "$LISTEN_MODE" = "unix" ] && echo "socket=$SOCKET_NAME"
} > "$LISTEN_META"
chmod 600 "$LISTEN_META"

echo "[*] Staging: $RANDOM_BIN (source removed=$DELETE_SOURCE)"
echo "[*] Fake name: $FAKE_NAME"
echo "[*] LISTEN_MODE=$LISTEN_MODE"
echo "[*] listen=$LISTEN_ARG"

if [ "$USE_CMDLINE_LISTEN" = "1" ]; then
    exec -a "$FAKE_NAME" "$RANDOM_BIN" -l "$LISTEN_ARG" &
else
    export APP_LISTEN="$LISTEN_ARG"
    exec -a "$FAKE_NAME" "$RANDOM_BIN" &
fi
PID=$!

(
    sleep 0.3
    rm -f "$RANDOM_BIN" 2>/dev/null || true
) &

sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
    echo "[!] Process died — check binary and listen address"
    rm -f "$RANDOM_BIN" "$LISTEN_META" 2>/dev/null || true
    exit 1
fi

if [ "$LISTEN_MODE" = "unix" ]; then
    if grep -q "@$SOCKET_NAME" /proc/net/unix 2>/dev/null; then
        echo "[*] unix abstract @$SOCKET_NAME is listening"
    else
        echo "[!] Warning: @$SOCKET_NAME not found in /proc/net/unix"
    fi
    if grep -qE ':(6992|69A2|69DC|6A94|ADCE|1B)' /proc/net/tcp 2>/dev/null; then
        echo "[!] Warning: suspicious TCP port still in /proc/net/tcp"
    else
        echo "[*] no frida-class TCP ports in /proc/net/tcp"
    fi
    echo "[*] adb forward tcp:$FORWARD_PORT localabstract:$SOCKET_NAME"
else
    if command -v netstat >/dev/null 2>&1; then
        LISTENING=$(netstat -tln 2>/dev/null | grep "127.0.0.1:$FORWARD_PORT" || true)
        if [ -n "$LISTENING" ]; then
            echo "[*] 127.0.0.1:$FORWARD_PORT is listening (tcp mode)"
        else
            echo "[!] Warning: 127.0.0.1:$FORWARD_PORT may not be listening"
        fi
    fi
    echo "[*] adb forward tcp:$FORWARD_PORT tcp:$FORWARD_PORT"
fi

fake_kworker_name() {
    printf "kworker/%s:%s" "$(rand_hex 2)" "$(rand_hex 1)"
}

(
    while kill -0 "$PID" 2>/dev/null; do
        for TID_DIR in /proc/$PID/task/*/; do
            COMM_FILE="$TID_DIR/comm"
            [ -f "$COMM_FILE" ] || continue

            TID=$(basename "$TID_DIR")
            COMM_NAME=$(cat "$COMM_FILE" 2>/dev/null)

            if [ "$TID" = "$PID" ]; then
                printf '%s' "$FAKE_NAME" > "$COMM_FILE" 2>/dev/null || true
                continue
            fi

            # Rename every worker thread: GLib resets gmain/gdbus faster than a filter-only loop.
            printf '%s' "$(fake_kworker_name)" > "$COMM_FILE" 2>/dev/null || true
        done
        sleep 0.05
    done
) &
MONITOR_PID=$!

echo "[*] PID=$PID Monitor=$MONITOR_PID"
echo "[*] Press Ctrl+C to stop"

trap "kill $MONITOR_PID 2>/dev/null; exit 0" INT TERM
wait "$PID" 2>/dev/null

kill $MONITOR_PID 2>/dev/null || true
rm -f "$LISTEN_META" 2>/dev/null || true
echo "[*] Stopped"
