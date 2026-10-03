#!/usr/bin/env bash
#
# Brings up a working swarm with one command: builds if needed, generates the
# TLS certificate on first run, starts every tracker listed in
# tracker_info.txt on a clean journal, and prints the client commands to paste.
#
#   ./demo.sh            start the trackers
#   ./demo.sh --stop     stop them and clean up
#   ./demo.sh --rebuild  force a recompile first
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACKER_DIR="$ROOT/tracker"
CLIENT_DIR="$ROOT/client"
RUN_DIR="$ROOT/.demo"
TRACKER_INFO="$TRACKER_DIR/tracker_info.txt"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim()  { printf '\033[2m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m*\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
die()  { printf '  \033[31mx\033[0m %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------- stop
if [[ "${1:-}" == "--stop" ]]; then
  bold "Stopping trackers"
  if [[ -f "$RUN_DIR/pids" ]]; then
    while read -r pid; do
      [[ -n "$pid" ]] || continue
      if kill "$pid" 2>/dev/null; then ok "stopped pid $pid"; fi
    done < "$RUN_DIR/pids"
    rm -f "$RUN_DIR/pids"
  else
    warn "no pid file; falling back to pattern match"
    pkill -f "$TRACKER_DIR/tracker " 2>/dev/null && ok "stopped by pattern" || warn "nothing running"
  fi
  rm -f "$RUN_DIR"/*.journal
  ok "journals cleared"
  exit 0
fi

# ---------------------------------------------------------------- platform
UNAME="$(uname -s)"
SSL_FLAGS=()
if [[ "$UNAME" == "Darwin" ]]; then
  command -v brew >/dev/null 2>&1 || die "Homebrew is needed on macOS to locate OpenSSL 3"
  OSSL="$(brew --prefix openssl@3 2>/dev/null)" || die "run: brew install openssl@3"
  [[ -d "$OSSL" ]] || die "run: brew install openssl@3"
  SSL_FLAGS=(-I"$OSSL/include" -L"$OSSL/lib")
  OPENSSL_BIN="$OSSL/bin/openssl"
else
  OPENSSL_BIN="openssl"
fi

# ---------------------------------------------------------------- build
build_one() {
  local dir="$1" src="$2" out="$3"
  ( cd "$dir" && g++ -std=gnu++17 -O2 -Wall -Wextra "$src" -o "$out" \
      "${SSL_FLAGS[@]}" -pthread -lssl -lcrypto 2>&1 | grep -E '\berror\b' ) && return 1
  [[ -x "$dir/$out" ]]
}

needs_build() {
  local bin="$1" src="$2"
  [[ ! -x "$bin" || "$src" -nt "$bin" ]]
}

bold "Building"
if [[ "${1:-}" == "--rebuild" ]] || needs_build "$TRACKER_DIR/tracker" "$TRACKER_DIR/tracker.cpp"; then
  build_one "$TRACKER_DIR" tracker.cpp tracker || die "tracker failed to compile"
  ok "tracker compiled"
else
  ok "tracker up to date"
fi
if [[ "${1:-}" == "--rebuild" ]] || needs_build "$CLIENT_DIR/client" "$CLIENT_DIR/client.cpp"; then
  build_one "$CLIENT_DIR" client.cpp client || die "client failed to compile"
  ok "client compiled"
else
  ok "client up to date"
fi

# ---------------------------------------------------------------- TLS cert
bold "TLS certificate"
if [[ -f "$TRACKER_DIR/server.crt" && -f "$TRACKER_DIR/server.key" ]]; then
  ok "already present"
else
  "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$TRACKER_DIR/server.key" -out "$TRACKER_DIR/server.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
    || die "could not generate a certificate"
  chmod 600 "$TRACKER_DIR/server.key"
  ok "generated tracker/server.crt"
fi
# The client verifies the tracker against this copy; without it the connection
# is still encrypted but unauthenticated.
cp -f "$TRACKER_DIR/server.crt" "$CLIENT_DIR/server.crt"
ok "trust anchor copied to client/"

# ---------------------------------------------------------------- trackers
[[ -f "$TRACKER_INFO" ]] || die "missing $TRACKER_INFO"
# Read the address list without `mapfile`, which macOS's bash 3.2 does not have.
ADDRS=()
while IFS= read -r addr; do
  addr="${addr%$'\r'}"
  case "$addr" in ''|\#*) continue ;; esac
  ADDRS+=("$addr")
done < "$TRACKER_INFO"
[[ ${#ADDRS[@]} -gt 0 ]] || die "$TRACKER_INFO lists no addresses"

mkdir -p "$RUN_DIR"
if [[ -f "$RUN_DIR/pids" ]]; then
  still_up=0
  while read -r p; do
    [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null && still_up=1
  done < "$RUN_DIR/pids"
  [[ $still_up -eq 1 ]] && warn "trackers already running - run ./demo.sh --stop first"
fi
rm -f "$RUN_DIR/pids" "$RUN_DIR"/*.journal

bold "Starting ${#ADDRS[@]} tracker(s)"
for i in "${!ADDRS[@]}"; do
  journal="$RUN_DIR/tracker_$i.journal"
  log="$RUN_DIR/tracker_$i.log"
  ( cd "$TRACKER_DIR" && exec ./tracker tracker_info.txt "$i" "$journal" ) >"$log" 2>&1 &
  echo $! >> "$RUN_DIR/pids"
  ok "[$i] ${ADDRS[$i]}  (log: .demo/tracker_$i.log)"
done

sleep 2
for i in "${!ADDRS[@]}"; do
  grep -q '\[tls\] enabled' "$RUN_DIR/tracker_$i.log" || warn "tracker $i may not have TLS enabled - see .demo/tracker_$i.log"
done

# ---------------------------------------------------------------- next steps
echo
bold "Swarm is up. Open two more terminals and paste:"
echo
dim "  # terminal 2 - the seeder"
echo "  cd $CLIENT_DIR && ./client 127.0.0.1:7001 tracker_info.txt"
echo
dim "  # terminal 3 - the downloader"
echo "  cd $CLIENT_DIR && ./client 127.0.0.1:7002 tracker_info.txt"
echo
bold "Then, in the seeder:"
cat <<'EOF'
  create_user alice pw
  login alice pw
  create_group demo
  upload_file demo ./some-file.bin        # quote the path if it has spaces
EOF
echo
bold "In the downloader:"
cat <<'EOF'
  create_user bob pw
  login bob pw
  join_group demo
EOF
echo
bold "Back in the seeder (the owner approves):"
cat <<'EOF'
  accept_request demo bob
EOF
echo
bold "Then in the downloader:"
cat <<'EOF'
  list_files demo
  download_file demo some-file.bin        # destination defaults to ./
  show_downloads                          # run again to watch progress
EOF
echo
dim "Stop everything with: ./demo.sh --stop"
