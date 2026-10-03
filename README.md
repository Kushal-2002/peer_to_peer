# Peer-to-Peer File Sharing System with a Replicated Tracker

A BitTorrent-style file sharing system written from scratch in C++17 on raw POSIX
sockets. Files are split into pieces, verified individually with SHA-1, and
downloaded in parallel from multiple peers at once. A replicated metadata tracker
handles authentication, group membership and peer discovery — but never carries
file data.

No external frameworks. ~4,000 lines of C++ across two binaries, plus a Python
benchmark harness that drives the real processes.

---

## Architecture

The system separates **metadata** from **bulk data**, and the two travel over
completely different paths:

```
         CONTROL PLANE — metadata only, no file bytes
  ┌──────────────┐   SYNC_* records   ┌──────────────┐
  │  tracker[0]  │◄──────────────────►│  tracker[1]  │
  │  :9000       │   (journaled,      │  :9001       │
  │              │    deduplicated)   │              │
  └──────┬───────┘                    └──────┬───────┘
         │ fsync before ack                  │
  ┌──────▼─────────┐              ┌──────────▼───────┐
  │tracker_0.journal│             │ tracker_1.journal│
  └────────────────┘              └──────────────────┘
         ▲                  ▲                  ▲
         │ upload_file      │ get_manifest     │ list_files
         │                  │ download_file    │
  ───────┼──────────────────┼──────────────────┼────────────
         │   DATA PLANE — 512 KiB pieces, peer ⇄ peer
  ┌──────┴─────┐     ┌──────┴─────┐     ┌──────┴─────┐
  │   peer A   │     │   peer B   │     │   peer C   │
  │ full seeder│     │ downloader │     │  partial   │
  ├────────────┤     ├────────────┤     ├────────────┤
  │REPL+tracker│     │REPL+tracker│     │REPL+tracker│
  │peer server │◄───►│peer server │◄───►│peer server │
  │download mgr│     │download mgr│     │download mgr│
  └────────────┘     └────────────┘     └────────────┘
       REQUEST_PIECE ──►      ◄── PIECE <idx> <len> + raw bytes
```

**No file byte ever passes through the tracker.** `download_file` returns only a
peer list (`OK peers:owner@ip:port,...`); the transfer itself is strictly
peer-to-peer. Throughput therefore scales with the number of seeders rather than
bottlenecking on a server.

---

## Design points

### Crash-consistent tracker state

Every mutation — user creation, group join, upload, leave, stop-share — is
appended to a write-ahead journal and `fsync`'d **before** the client receives
its acknowledgement. If a client saw `OK`, that record survives power loss.

On startup the tracker replays the journal before any thread is spawned, so no
peer or client can ever observe a tracker that has forgotten something it
committed. A record left half-written by a crash is detected (a complete record
always ends in a newline), discarded, and truncated off the file so the next
append cannot glue itself onto a partial line.

Replay feeds records through the *same* handler as live replication traffic, so
recovery and replication share one code path rather than drifting apart.

### Tracker replication

Each tracker opens a persistent sync link to every other tracker listed in
`tracker_info.txt`, retrying on failure. On connect it streams its entire journal
to the peer; records are deduplicated by exact match, making replay idempotent.
Clients walk their tracker list until one answers, so either tracker can serve
any request.

This is **eventually consistent** — a mutation is applied and acknowledged
locally before being pushed to the peer, so a brief divergence window exists. See
[Known limitations](#known-limitations).

### Rarest-first piece selection

Before downloading, the client asks every peer which pieces it holds
(`QUERY_HAVE`) and sorts the work queue so the scarcest pieces are fetched first.
This protects swarm health: if the only peer holding piece 7 disconnects, the file
becomes undownloadable for everyone.

### Partial-share seeding

A download registers itself as a shareable partial file the moment it starts,
tracking a bitmap of verified pieces. Incoming requests are served from that
bitmap — a verified piece is sent, anything else is explicitly refused so the
requester retries elsewhere instead of receiving a hole.

Without this, every peer advertises "I have everything", piece availability is
uniform, and rarest-first ordering has nothing to order. **Registering a download
as a partial share is what makes some pieces genuinely scarcer than others.**

### Integrity

The manifest carries a SHA-1 hash per 512 KiB piece plus one for the whole file.
Each received piece is hashed and compared before being written to the `.part`
file; a mismatch requeues it, up to five attempts, typically landing on a
different peer. The full-file hash is checked before the `.part` is renamed into
place.

### Password storage

Passwords are hashed with PBKDF2-HMAC-SHA256, 100,000 iterations, with a random
16-byte salt per user. Hashing happens at the edge where the plaintext arrives, so
the plaintext never reaches stored state, the journal, or the replication link.
The key derivation runs outside the mutex so concurrent logins are not serialised
behind one deliberately slow operation.

---

## Build

Both binaries link OpenSSL 3.

### Linux

```bash
cd tracker && g++ -std=gnu++17 -O2 -Wall -Wextra tracker.cpp -o tracker -pthread -lssl -lcrypto
cd ../client && g++ -std=gnu++17 -O2 -Wall -Wextra client.cpp -o client -pthread -lssl -lcrypto
```

### macOS

Homebrew's OpenSSL is keg-only, so the paths must be given explicitly:

```bash
OSSL=$(brew --prefix openssl@3)

cd tracker && g++ -std=gnu++17 -O2 -Wall -Wextra tracker.cpp -o tracker \
  -I"$OSSL/include" -L"$OSSL/lib" -pthread -lssl -lcrypto

cd ../client && g++ -std=gnu++17 -O2 -Wall -Wextra client.cpp -o client \
  -I"$OSSL/include" -L"$OSSL/lib" -pthread -lssl -lcrypto
```

---

## Running

`tracker_info.txt` holds one `host:port` per line, one per tracker instance:

```
127.0.0.1:9000
127.0.0.1:9001
```

### Start the trackers

Each instance is given its own **0-based line number** in that file:

```bash
cd tracker
./tracker tracker_info.txt 0          # listens on :9000
./tracker tracker_info.txt 1          # listens on :9001, in another shell
```

State persists in `tracker_<index>.journal` by default; pass a third argument to
override. Type `quit` into a tracker's stdin for a graceful shutdown.

### Start a client

```bash
cd client
./client 127.0.0.1:7001 tracker_info.txt
```

The first argument is the address this peer advertises to others. Pass only an IP
to let the OS choose a free port. The client starts its peer listener *before*
contacting any tracker, since the address it advertises must already be live.

---

## Walkthrough

Two clients, one file. In the first client:

```
> create_user alice secret123
> login alice secret123
> create_group study
> upload_file study ./myfile.bin
```

In the second:

```
> create_user bob hunter2
> login bob hunter2
> join_group study
```

Back in Alice's client (she owns the group, so she approves):

```
> list_requests study
> accept_request study bob
```

Now Bob can list and fetch:

```
> list_files study
> show_seeders study myfile.bin
> download_file study myfile.bin ./downloaded.bin
> show_downloads
```

`show_downloads` prints a status tag per job — `C` complete, `D` downloading,
`F` failed. Bob begins serving verified pieces to other peers as soon as the
first one lands.

---

## Command reference

| Command | Description |
|---|---|
| `create_user <user> <pass>` | Register. Password is hashed at the tracker. |
| `login <user> <pass>` | Authenticate on this connection. |
| `logout` | End the session. |
| `create_group <gid>` | Create a group; you become its owner. |
| `join_group <gid>` | Request membership (owner must approve). |
| `leave_group <gid>` | Leave a group. |
| `list_groups` | All groups on the tracker. |
| `list_requests <gid>` | Pending join requests (owner only). |
| `accept_request <gid> <user>` | Approve a request (owner only). |
| `list_files <gid>` | Files shared in a group. |
| `upload_file <gid> <file_path>` | Hash the file locally and announce it. |
| `download_file <gid> <filename> <dest>` | Multi-peer parallel download. |
| `show_downloads` | Status of all download jobs. |
| `show_seeders <gid> <filename>` | Which peers currently hold the file. |
| `stop_share <gid> <filename>` | Stop seeding a file. |
| `quit` / `exit` | Shut down the client. |

---

## Wire protocols

Three newline-delimited text protocols, all debuggable with `telnet`.

**Client → Tracker** — the commands above, plus `get_manifest <gid> <filename>`,
which returns file size, full SHA-1, piece count, peer list and every piece hash.

**Tracker ↔ Tracker** — `SYNC_INIT` to open a link, then `SYNC_CREATE_USER`,
`SYNC_CREATE_GROUP`, `SYNC_JOIN_REQUEST`, `SYNC_ACCEPT_REQUEST`,
`SYNC_LEAVE_GROUP`, `SYNC_UPLOAD_FILE`, `SYNC_STOP_SHARE`.

**Peer ↔ Peer** — the data plane:

```
QUERY_HAVE <owner> <filename>
  → OK HAVE <idx> <idx> ...      pieces this peer holds
  → OK HAVE ALL <n>              holds the complete file
  → OK HAVE NONE                 holds nothing yet

REQUEST_PIECE <owner> <filename> <idx>
  → PIECE <idx> <len>\n<len raw bytes>
  → ERR no_such_piece            not held, or not yet verified
```

---

## Benchmarks

`benchmark/bench.py` compiles and drives the **real** binaries as subprocesses,
registering users and groups through the actual CLI and timing real downloads.
Nothing is simulated or estimated.

```bash
cd benchmark
python3 bench.py                              # defaults, finishes in seconds
python3 bench.py --filesize-kb 65536 --peer-counts 1,2,4,8 --repeat 3
```

It measures three things: peer scaling (one downloader, varying seeders), client
scaling (fixed seeders, concurrent downloaders), and a centralized single-source
TCP baseline written inside the harness for comparison. Results print and are
written to `results.csv`.

### Measured — 2 MB file, loopback, single machine

| Configuration | Time | Throughput |
|---|---|---|
| P2P, 1 seeder | 0.038 s | 52.98 MB/s |
| P2P, 2 seeders | 0.025 s | **79.53 MB/s** |
| Centralized, 1 source | 0.001 s | ~1,700 MB/s |

**Adding a second seeder made the download 1.5× faster** — the multi-peer path
doing exactly what it is designed to do.

In absolute terms the naive centralized baseline still wins at this file size, for
three reasons worth being explicit about: a 2 MB file is only four 512 KiB pieces,
so there is very little to parallelise; every peer here is a process on one
machine reading from one disk, so seeders compete for a single device instead of
contributing independent bandwidth; and the centralized baseline does a single
sequential read with no chunking and no hashing, so it pays none of the integrity
cost the P2P path pays per piece.

**The file size at which P2P overtakes the centralized baseline has not been
measured.** Finding it requires a much larger file and ideally separate hosts.

---

## Project structure

```
tracker/
  tracker.cpp          auth, groups, file manifests, journal, tracker sync
  tracker_info.txt     one host:port per line
client/
  client.cpp           REPL, peer server, multi-peer download manager
  tracker_info.txt     same list, used for failover
benchmark/
  bench.py             drives the real binaries, measures real transfers
  diag_multipeer.py    multi-peer diagnostic
  results.csv          measured output
```

Each binary is a single translation unit. `client.cpp` contains the interactive
REPL, the piece-serving peer server, and the download scheduler; `tracker.cpp`
contains the command dispatcher, the journal, and the replication threads.

---

## Known limitations

Honest about what this does and does not do:

- **Eventually consistent replication, no consensus.** A mutation is
  acknowledged locally before it reaches the other tracker, so a client that
  writes to one and immediately reads from the other can miss its own write.
  Worse, two trackers that cannot see each other will both accept conflicting
  writes — the same username registered on both during a partition leaves each
  tracker holding a different password hash permanently, because deduplication
  matches whole records and conflicting records are not identical. Resolving this
  properly needs a total ordering of writes or an explicit merge rule.
- **No transport encryption.** Passwords are hashed at rest and in the journal,
  but travel to the tracker in cleartext. TLS is the fix.
- **The peer protocol is unauthenticated.** Group membership is enforced by the
  tracker but not peer-to-peer, so any host that can reach a peer's port and
  knows an owner and filename can request pieces.
- **SHA-1 for piece integrity.** Sufficient against accidental corruption, not
  against a deliberate collision. SHA-256 would be a small change.
- **No choking / tit-for-tat.** Real BitTorrent rations upload bandwidth toward
  peers that reciprocate, which is what makes it resistant to freeloading. This
  serves all requesters equally.
- **Thread per connection.** Simple and correct, but one OS thread per connection
  does not scale to thousands of peers; an event loop with a small thread pool
  would.
- **Sessions are keyed by socket**, so background operations must reconnect and
  re-authenticate. A session token would decouple the two.
- **Single-machine testing only.** Everything runs over `127.0.0.1`, so no result
  here reflects real network latency, packet loss or NIC contention. No NAT
  traversal or DHT.
- **Fixed 512 KiB piece size** regardless of file size, and filenames containing
  spaces break the whitespace tokenizer.

---

## Implementation notes

Written against raw POSIX syscalls rather than C++ iostreams where it matters:
the journal uses `write` plus `fsync` so the durability point is explicit, and
message framing is hand-rolled (`send_all` loops on partial writes; `recv_line`
reads to a newline) because TCP provides a byte stream with no message
boundaries.
