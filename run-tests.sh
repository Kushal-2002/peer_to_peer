#!/usr/bin/env bash
#
# Runs every suite and prints one summary. Point of this script: re-verifying
# the project should be one command, so there is never a reason to rely on a
# stale record of what passed last time.
#
#   ./run-tests.sh              everything
#   ./run-tests.sh --quick      skip the benchmark (which takes minutes)
#   ./run-tests.sh --bench-only just the benchmark
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

QUICK=0; BENCH_ONLY=0
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    --bench-only) BENCH_ONLY=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m+\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m-\033[0m %s\n' "$1"; }

SSL_FLAGS=()
if [[ "$(uname -s)" == "Darwin" ]]; then
  OSSL="$(brew --prefix openssl@3 2>/dev/null)" || { echo "need: brew install openssl@3" >&2; exit 2; }
  SSL_FLAGS=(-I"$OSSL/include" -L"$OSSL/lib")
fi

FAILED=0
note() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; FAILED=1; fi }

# Nothing left over from a previous run, or ports and journals collide.
pkill -f 'tracker tracker_info' >/dev/null 2>&1
pkill -f '/client 127.0.0.1'    >/dev/null 2>&1
sleep 1
rm -f tracker/*.journal 2>/dev/null

echo
bold "Build"
g++ -std=gnu++17 -O2 -Wall -Wextra tracker/tracker.cpp -o tracker/tracker \
    "${SSL_FLAGS[@]}" -pthread -lssl -lcrypto 2>/dev/null
note $? "tracker compiles"
g++ -std=gnu++17 -O2 -Wall -Wextra client/client.cpp -o client/client \
    "${SSL_FLAGS[@]}" -pthread -lssl -lcrypto 2>/dev/null
note $? "client compiles"

if [ "$BENCH_ONLY" -eq 0 ]; then
  echo
  bold "Journal tests (unit)"
  g++ -std=gnu++17 -O2 -Wall -Wextra tests/test_journal.cpp -o tests/test_journal \
      "${SSL_FLAGS[@]}" -pthread -lssl -lcrypto 2>/dev/null
  if [ $? -ne 0 ]; then
    bad "test_journal failed to compile"; FAILED=1
  else
    ./tests/test_journal > /tmp/journal_out.txt 2>&1
    st=$?
    sed 's/\x1b\[[0-9;]*m//g' /tmp/journal_out.txt | grep -E 'passed|failed$' | sed 's/^/    /'
    note $st "journal suite"
  fi

  echo
  bold "Integration tests"
  # Needs its own trackers, which it starts and stops itself.
  python3 tests/test_integration.py --skip-build > /tmp/integ_out.txt 2>&1
  st=$?
  sed 's/\x1b\[[0-9;]*m//g' /tmp/integ_out.txt | grep -E '^  (PASS|FAIL|SKIP)|passed,' | sed 's/^/  /'
  note $st "integration suite"
fi

if [ "$QUICK" -eq 0 ]; then
  echo
  bold "Benchmark"
  echo "  (6 trials per configuration at 16 MB; takes a few minutes)"
  ( cd benchmark && python3 bench.py --skip-build --filesize-kb 16384 \
      --peer-counts 1,2,4 --downloader-counts 1,2 --repeat 6 ) \
      > /tmp/bench_out.txt 2>&1
  st=$?
  sed -n '/=== Summary ===/,$p' /tmp/bench_out.txt | sed 's/^/  /'
  note $st "benchmark completed"
  echo
  echo "  NOTE: this overwrites benchmark/results.csv, which the README's figures"
  echo "  are computed from. If you are not updating those figures, restore it:"
  echo "      git checkout benchmark/results.csv"
fi

pkill -f 'tracker tracker_info' >/dev/null 2>&1
rm -f tracker/*.journal 2>/dev/null

echo
if [ "$FAILED" -eq 0 ]; then
  bold "All suites passed."
else
  bold "SOMETHING FAILED - see /tmp/journal_out.txt, /tmp/integ_out.txt, /tmp/bench_out.txt"
fi
echo
exit $FAILED
