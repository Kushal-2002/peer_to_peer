# Benchmark: P2P vs. Centralized File Distribution

This directory contains `bench.py`, which does the thing the assignment brief
and `Performance_Report.pdf` describe but the original project never actually
built: it **runs** the real `tracker`/`client` binaries and **measures** real
download times, instead of reporting synthesized/estimated numbers.

It does not modify `tracker.cpp` or `client.cpp` in any way — it only
compiles and drives them as subprocesses through their existing CLI/stdin
protocol.

## What it measures

1. **Experiment 1 — peer scaling.** One downloader fetches the same file
   while the number of seeders holding it varies (1, 2, 4 by default).
   Shows whether the P2P system's multi-peer download actually gets faster
   as more sources become available.

2. **Experiment 2 — client scaling (P2P).** A fixed small swarm of seeders
   (2 by default) serves several downloaders **simultaneously** (1, 2, 4 by
   default), measuring how per-downloader time changes under concurrent
   load.

3. **Centralized baseline.** A tiny single-source TCP file server (written
   directly in `bench.py`, not part of the project) serves the same file to
   the same downloader counts, sequentially and with no chunking/multi-peer
   parallelism — representing the "everyone downloads from one central
   server" model the assignment asks you to compare against.

Results print to the console and are written to `results.csv`.

## Running it

```
cd benchmark
python3 bench.py
```

First run compiles `tracker` and `client` using the exact commands from the
project's own README. Subsequent runs can skip that with `--skip-build`.

Useful flags:

```
python3 bench.py --filesize-kb 8192          # bigger test file (8MB)
python3 bench.py --peer-counts 1,2,4,8
python3 bench.py --downloader-counts 1,2,4,8
python3 bench.py --seeder-count-exp2 4
python3 bench.py --repeat 3                  # average multiple trials
python3 bench.py -v                          # dump raw client stdin/stdout
```

Defaults are intentionally small (2MB file, seeder/downloader counts up to
4) so a full run finishes in well under a minute on a normal laptop. Bump
`--filesize-kb` up if you want numbers closer to the report's 200MB/1GB
scenarios — expect the run to take proportionally longer.

## How it works, briefly

- Starts both tracker instances from `tracker/tracker_info.txt`
  (`127.0.0.1:9000` / `:9001`), exactly as the project's README describes.
- For each trial, spawns fresh `client` subprocesses (one per seeder/
  downloader), each bound to its own loopback port, each in its own scratch
  working directory (so `client.log` files don't collide).
- Drives each client's interactive REPL by writing lines to its stdin and
  reading its stdout until the `> ` prompt reappears — the same mechanism a
  human typing into the client would trigger, nothing internal is touched.
- Registers users/groups/uploads through the real protocol
  (`create_user`, `login`, `create_group`/`join_group`/`accept_request`,
  `upload_file`), then times `download_file` by polling `show_downloads`
  until the job's status tag flips to `C` (success) or `F` (failure).
- Every client process is sent `quit` and cleaned up at the end of each
  trial; both trackers are shut down at the end of the whole run.

## Limitations (be upfront about these)

- **Single machine, loopback only.** All "peers" are processes on the same
  host talking over `127.0.0.1`. There's no real network latency, packet
  loss, or separate-NIC contention — the project's own `tracker_info.txt`
  is loopback-only too, so this matches how the system is actually
  configured to run, but it means these numbers say nothing about a real
  multi-host deployment.
- **Shared disk/CPU.** Every seeder is reading the *same* underlying file
  from the *same* disk, and hashing/CPU work from all client processes
  competes for the same cores. At high concurrency this can understate the
  benefit of a real distributed swarm (where seeders would be on separate
  machines with separate disks) and overstate contention compared to a
  real deployment.
- **Small default file sizes.** Chosen for a fast demo run, not to
  reproduce the report's 1GB numbers. Piece-verification (SHA1) overhead
  and disk I/O costs scale with file size, so trends may shift at much
  larger sizes — increase `--filesize-kb` to explore that.
- **The centralized baseline is intentionally naive** (single thread per
  connection, sequential full-file read/send, no chunking) since that's
  the "centralized file transfer model" the assignment brief asks you to
  contrast against — a production file server (CDN, HTTP range requests,
  etc.) would behave differently and isn't what's being modeled here.

These numbers are real measurements of this codebase's actual behavior on
your machine — unlike `Performance_Report.pdf`, which states its figures
are synthesized estimates, not measured results.
