#!/usr/bin/env bash
# Apply anti-detection source patches to Frida 16.2.1 submodules (re.nginx + APP_LISTEN).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$ROOT/frida-core"

if [[ ! -d "$CORE/lib/base" ]]; then
  echo "frida-core submodule missing — run: git submodule update --init --recursive"
  exit 1
fi

patch_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    echo "skip missing: $f"
    return 0
  fi
  sed -i 's/re\.frida\./re.nginx./g' "$f"
  echo "patched: $f"
}

patch_file "$CORE/lib/base/session.vala"
patch_file "$CORE/src/linux/frida-helper-types.vala"
patch_file "$CORE/src/darwin/frida-helper-types.vala"
patch_file "$CORE/src/windows/frida-helper-types.vala"

SERVER="$CORE/server/server.vala"
if [[ -f "$SERVER" ]]; then
  sed -i 's/re\.frida\.server/re.nginx.server/g' "$SERVER"
  if ! grep -q 'APP_LISTEN' "$SERVER"; then
    sed -i '/if (output_version)/,/Environment.set_verbose_logging_enabled/ {
      /Environment.set_verbose_logging_enabled/i\
\
\t\tif (listen_address == null) {\
\t\t\tlisten_address = Environment.get_variable ("APP_LISTEN");\
\t\t}
    }' "$SERVER"
  fi
  echo "patched: $SERVER"
fi

echo "Magic patches applied."
