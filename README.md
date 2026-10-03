# Peer-to-Peer File Sharing System with a Replicated Tracker

A BitTorrent-style file sharing system written from scratch in C++17 on raw POSIX
sockets. Files are split into pieces, verified individually with SHA-1, and
downloaded in parallel from multiple peers at once. A replicated metadata tracker
handles authentication, group membership and peer discovery over TLS — but never
carries file data.

No external frameworks. ~5,100 lines of C++ across two binaries, plus a Python
benchmark harness that drives the real processes.

---

## Architecture

The system separates **metadata** from **bulk data**, and the two travel over
completely different paths:

```
      CONTROL PLANE — metadata only, no file bytes (TLS 1.2+)
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
         │ (over TLS)       │ download_file    │ (over TLS)
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

### Credentials: at rest and in transit

These are two separate problems, and both are addressed.

**At rest**, passwords are hashed with PBKDF2-HMAC-SHA256, 100,000 iterations,
with a random 16-byte salt per user. Hashing happens at the edge where the
plaintext arrives, so the plaintext never reaches stored state, the journal, or
the replication link. The key derivation runs outside the mutex so concurrent
logins are not serialised behind one deliberately slow operation.

**In transit**, client-to-tracker connections run over TLS 1.2+. Hashing protects
a stolen credential database; it does nothing for an attacker watching the
network, who would otherwise read `login alice secret123` straight off the wire.

The tracker serves one port for both clients and sync peers, which creates an
ordering problem: a TLS handshake has to complete before any application data is
read, but the tracker identifies a sync peer *by* reading its first line
(`SYNC_INIT`). It is resolved by inspecting the first byte with `MSG_PEEK`, which
does not consume it — a TLS handshake always begins with a `0x16` record byte,
while `SYNC_INIT` begins with `S`. The connection is routed accordingly and
either path then sees the full stream.

TLS state is keyed by file descriptor, so `send_line(fd, ...)` and
`recv_line(fd, ...)` transparently use `SSL_write`/`SSL_read` when a descriptor
has TLS attached and `send`/`recv` otherwise. Because all socket I/O in both
programs already funnelled through those two helpers, no call site above them
changed.

Peer-to-peer connections stay plaintext deliberately: they carry file pieces and
no credentials, every piece is independently SHA-1 verified against the manifest,
and encrypting bulk transfer would add CPU cost to the download path for no
confidentiality gain. The tracker-to-tracker sync link is also still plaintext —
see [Known limitations](#known-limitations).

### Session tokens

A session used to be identified by the socket it was created on
(`sessions[fd] = user`). That had two consequences. A client's background threads
open their own connections, so to authenticate them the client had to keep the
user's **plaintext password in memory** for the life of the process. And every
such connection re-ran the login path — meaning a full 100,000-iteration PBKDF2
verification, a cost that exists to slow down password cracking, placed on a
routine operation.

Login now returns a signed token:

```
v1:<username-hex>:<expiry-unix>:<nonce-hex>:<hmac-sha256-hex>
```

The nonce is what makes each token unique. Without it the payload is only
username plus expiry, so logging out and immediately back in within the same
second mints a byte-identical token — one the logout had just added to the
revocation set, leaving the new session holding a token the tracker refuses.

The token is **stateless**. It carries the username and an expiry, authenticated
by an HMAC over both using a secret shared by every tracker (`session.key`,
generated on first run). Verification recomputes the HMAC and compares in
constant time, so no tracker stores the token, replicates it, or writes it to the
journal. That last point is what makes it work: a client's background announces
round-robin across trackers, so a token issued by one must be accepted by the
other — and a signature achieves that without any shared state at all.

The client keeps the token and discards the password after login. Fresh
connections send `auth <token>` instead of `login <user> <pass>`, turning a
deliberately slow key derivation into a hash comparison.

The trade-off is the same one JWTs make: a token cannot be withdrawn before it
expires, because nothing is looked up to validate it. `logout` records the token
in an in-memory revocation set, which is per-tracker and lost on restart. Expiry
(12 hours by default) is the real bound; revocation is best-effort.

### Filenames with spaces

Every protocol here is newline-delimited text split on whitespace, so a filename
containing a space used to be torn into two fields and the command simply failed.
Two separate things had to change.

**What you type.** The client's command parser now honours double quotes and a
backslash escape, so a path with spaces is given as `"my holiday video.mp4"` or
`my\ holiday\ video.mp4`. Unquoted input splits on whitespace exactly as before.

**What goes on the wire.** Filenames are percent-encoded whenever they are
transmitted — tracker commands, sync records, the journal, and the peer protocol
— which keeps each one a single whitespace-free token:

```
upload_file vids my%20holiday%20video.mp4 2500000 <sha1> 5 ...
QUERY_HAVE seeder my%20holiday%20video.mp4
```

In memory, and in anything shown to a user, a filename is always the real decoded
name. Encoding happens at the moment of transmission and decoding immediately on
receipt, so `list_files` prints `my holiday video.mp4`, not the escaped form.

Only `%` and characters that would break tokenisation or line framing are
escaped, and decoding treats `%` as an escape only when followed by two valid hex
digits — so a name that was never encoded decodes to itself, which keeps journals
written before this change replayable.

A length-prefixed binary framing would also solve this, and would handle
arbitrary bytes without needing an escape character at all. It was not chosen
because every tracker handler receives a pre-split `vector<string>`: length
prefixes would mean parsing each message field by field instead, rewriting every
handler rather than adding two helpers. The text protocol also stays readable on
the wire, which is worth keeping.

---

## Quick start

```bash
./demo.sh
```

Builds anything stale, generates the TLS certificate and the token signing
secret on first run, starts every tracker listed in `tracker_info.txt` on a
clean journal, copies the trust anchor to `client/`, and prints the client
commands to paste. `./demo.sh --stop` shuts the trackers down and clears the
journals; `./demo.sh --rebuild` forces a recompile.

Tracker logs go to `.demo/tracker_<n>.log`. The sections below cover doing all
of it by hand.

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

### Generate a TLS certificate

The tracker needs a certificate and key before it will accept encrypted client
connections. A self-signed pair is fine for local use:

```bash
cd tracker
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 server.key
cp server.crt ../client/server.crt     # the client's trust anchor
```

The `subjectAltName` matters: without it the client cannot verify the hostname
and falls back to encryption without authentication.

Neither file is committed — the key is secret, and the certificate is per
deployment. The same applies to `session.key`, which the tracker generates on
first run and which **must be identical on every tracker**; copy it across, or
override the path with `TRACKER_SESSION_KEY`. Override the paths with `TRACKER_TLS_CERT` / `TRACKER_TLS_KEY` on the
tracker and `TRACKER_TLS_CA` on the client.

Behaviour when files are missing is deliberately asymmetric. The tracker falls
back to plaintext with a loud warning, so an existing deployment is not broken by
upgrading. The client **refuses to run** without a TLS context, because the
alternative is silently transmitting a password in the clear. If the client has a
TLS context but no trust anchor, it connects encrypted-but-unverified and says
so: passive sniffing is defeated, an active man-in-the-middle is not.

### Tracker configuration

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

`show_downloads` reports progress per job, drawn from counters the worker
threads already maintain:

```
[R] [study] my holiday video.mp4
      ████████████░░░░░░  68%   21/31 pieces   10.6 MB / 15.5 MB   112.4 MB/s
[C] [study] report.pdf
      ██████████████████ 100%   4/4 pieces     1.9 MB / 1.9 MB     88.1 MB/s
```

The tag is `Q` queued, `R` running, `C` complete, `F` failed, `X` cancelled. The
rate is measured over the job's own elapsed time, so a finished job keeps
reporting the rate it actually achieved rather than one that decays as the
process keeps running.

Bob begins serving verified pieces to other peers as soon as the first one
lands, so a second downloader joining mid-transfer can already fetch from him.

---

## Command reference

| Command | Description |
|---|---|
| `create_user <user> <pass>` | Register. Password is hashed at the tracker. |
| `login <user> <pass>` | Authenticate; returns a session token. |
| `auth <token>` | Authenticate a connection with a token instead of a password. Used by the client's background threads. |
| `logout` | End the session. |
| `create_group <gid>` | Create a group; you become its owner. |
| `join_group <gid>` | Request membership (owner must approve). |
| `leave_group <gid>` | Leave a group. |
| `list_groups` | All groups on the tracker. |
| `list_requests <gid>` | Pending join requests (owner only). |
| `accept_request <gid> <user>` | Approve a request (owner only). |
| `list_files <gid>` | Files shared in a group. |
| `upload_file <gid> <file_path>` | Hash the file locally and announce it. Quote paths containing spaces: `upload_file g "my file.bin"`. |
| `download_file <gid> <filename> [dest]` | Multi-peer parallel download. Destination defaults to `./<filename>`. Quote names containing spaces. |
| `show_downloads` | Progress of all download jobs: bar, percentage, pieces, bytes and rate. |
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

### Measured — 16 MB file, 6 trials each, loopback, single machine

Recomputable from the committed `results.csv`. One downloader, varying seeders:

| Seeders | Mean | Range | Spread |
|---|---|---|---|
| 1 | 303.23 MB/s | 217.6 – 443.0 | **74%** |
| 2 | 431.43 MB/s | 421.3 – 454.1 | 8% |
| 4 | 415.06 MB/s | 375.0 – 424.4 | 12% |

**Two findings are solid, and one is not.**

Solid: a multi-peer download reliably reaches **~430 MB/s**, and that figure is
stable — 8% spread across six trials. Also solid: **adding a third and fourth
seeder gains nothing.** On a single machine every seeder reads the same file from
the same disk, so two saturate it and the bottleneck moves off peer availability
onto that device. On separate hosts with independent disks the curve would be
expected to keep rising.

Not solid: **the speedup ratio.** The single-seeder baseline varies 74% run to
run — 217 MB/s on one trial, 443 MB/s on another, which is as fast as two
seeders managed. Almost certainly the OS page cache: when the source file is
already resident from an earlier trial the read runs at memory speed, and with
one seeder that dominates the measurement, while with two or more the
parallelism masks it.

Because the baseline is the denominator, repeating the whole six-trial sweep
produced a different ratio every time:

| Run | Ratio | 1-seeder baseline |
|---|---|---|
| A | 1.70× | 246 MB/s |
| B | 1.87× | 231 MB/s |
| C | 1.42× | 303 MB/s |

So **no speedup figure is quoted here**, and that is the correct conclusion
rather than a gap. Pinning the ratio down would need the page cache controlled
between trials and ideally separate hosts, which this setup cannot provide.
Quoting any single one of those three numbers would be picking a favourite.

Getting to that conclusion took four attempts:

| Attempt | Setup | Outcome |
|---|---|---|
| 1 | 2 MB, 1 trial | 1.5× — noise. A repeat showed 2 seeders *slower* than 1. |
| 2 | 16 MB, 3 trials | 1.45× — the sample caught a low outlier. |
| 3 | 16 MB, 6 trials | 1.70×, then 1.87× on a repeat. |
| 4 | 16 MB, 6 trials, spread examined | Baseline varies 74%; the ratio is not measurable here. |

The lesson is worth more than the number: report the spread alongside the mean,
and when the spread swamps the effect, say so instead of quoting the mean.

For comparison, the centralized baseline averaged ~3,059 MB/s with one downloader
and ~2,133 MB/s with two. **It still wins in absolute terms at 16 MB, by roughly
7×**, for three reasons worth being explicit about: all peers share one disk and
one set of cores, so the swarm cannot contribute independent bandwidth; the
baseline does a single sequential read with no chunking and no hashing, so it pays
none of the per-piece integrity cost; and there is no network latency on loopback,
which is precisely the cost that multi-peer parallelism exists to hide. The test
environment flatters the baseline.

**The file size at which P2P overtakes the centralized baseline has not been
measured** — it was not reached at 16 MB. Finding it requires a much larger file
and, more importantly, separate hosts.

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

## Tests

```bash
# Linux
g++ -std=gnu++17 -O2 -Wall -Wextra tests/test_journal.cpp \
    -o tests/test_journal -pthread -lssl -lcrypto && ./tests/test_journal

# macOS
OSSL=$(brew --prefix openssl@3)
g++ -std=gnu++17 -O2 -Wall -Wextra tests/test_journal.cpp \
    -o tests/test_journal -I"$OSSL/include" -L"$OSSL/lib" \
    -pthread -lssl -lcrypto && ./tests/test_journal
```

19 tests, 86 assertions, covering the journal — the code the crash-consistency
claim rests on. Replay rebuilding users, groups, membership and file manifests;
torn-record detection and truncation; append-after-truncation; deduplication;
CRLF, blank, unknown and malformed records; a full crash-and-restart cycle; and
durability of an append.

`tracker.cpp` is one translation unit with its own `main()`, so the test
includes it with `main` renamed aside. That gives the tests the real functions
and real global state with no refactor, and no sockets, ports or timing.

### What the suite is checked against

A passing suite proves nothing unless it can fail, so each test was validated by
deliberately breaking the code and confirming the tests notice:

| Mutation | Result |
|---|---|
| Skip truncating the torn tail | caught — 6 assertions fail |
| Stop deduplicating identical records | caught — 2 assertions fail |
| Never reopen the journal for append | caught |
| Drop `wire_decode` on replayed filenames | caught |
| Remove the `npos` replay guard | *not* caught — unreachable while truncation works, so the mutation is equivalent |

That exercise found a real latent bug. The replay loop advances with
`pos = eol + 1`; with no trailing newline `find` returns `npos`, so `pos` wraps
to **0** and the loop replays the journal endlessly — a torn journal would have
hung the tracker at startup rather than failing. Truncation was the only thing
preventing it. The loop now checks for `npos` explicitly and stops with a
diagnostic, verified by disabling truncation *and* the resize together: that
combination hung before the guard and now exits in under a second.

### Not covered

- **`fsync` cannot be verified in-process.** Whether the data reached the
  platter is invisible to a test in the same process — the page cache serves the
  read either way. Proving it needs process-kill or block-layer fault injection.
- Only the journal is covered. The piece scheduler, the peer protocol and the
  TLS and token paths have no unit tests; they are exercised by `bench.py` and
  by hand.

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
- **The tracker-to-tracker sync link is still plaintext.** It carries PBKDF2
  credentials rather than plaintext passwords, so the exposure is smaller, but it
  is exposure. It was left unencrypted because a sync connection has one thread
  writing broadcasts while another reads inbound records, and sharing one SSL
  object between a concurrent reader and writer is not safe. Fixing it properly
  means serialising access per connection or giving each direction its own
  connection — not a large change, but a real one.
- **The peer protocol is unauthenticated and unencrypted.** Group membership is
  enforced by the tracker but not peer-to-peer, so any host that can reach a
  peer's port and knows an owner and filename can request pieces. Piece contents
  are integrity-checked but not confidential.
- **Self-signed certificates only.** There is no CA infrastructure, so the
  client's trust anchor is the tracker's own certificate, distributed by hand.
  Fine for a known deployment; it does not scale to arbitrary peers.
- **SHA-1 for piece integrity.** Sufficient against accidental corruption, not
  against a deliberate collision. SHA-256 would be a small change.
- **No choking / tit-for-tat.** Real BitTorrent rations upload bandwidth toward
  peers that reciprocate, which is what makes it resistant to freeloading. This
  serves all requesters equally.
- **Thread per connection.** Simple and correct, but one OS thread per connection
  does not scale to thousands of peers; an event loop with a small thread pool
  would.
- **Session tokens cannot be revoked before expiry.** Validation is a signature
  check with no lookup, so `logout` can only add the token to an in-memory,
  per-tracker revocation set that is lost on restart. A token logged out on one
  tracker still verifies on the other until it expires. Shortening the TTL or
  replicating revocations would tighten this.
- **The token signing secret must be copied between trackers by hand.** A tracker
  without the shared `session.key` rejects every token the other issued, and the
  failure is silent from the client's side beyond an `ERR invalid_token`.
- **Single-machine testing only.** Everything runs over `127.0.0.1`, so no result
  here reflects real network latency, packet loss or NIC contention. No NAT
  traversal or DHT.
- **Fixed 512 KiB piece size** regardless of file size. A 2 MB file is only four
  pieces, which leaves little for multi-peer parallelism to work with.
- **Group and user names still cannot contain whitespace.** Only filenames are
  percent-encoded; a group id or username with a space would be split into two
  tokens. The encoding helpers would extend to those fields unchanged, it has
  just not been done.

---

## Implementation notes

Written against raw POSIX syscalls rather than C++ iostreams where it matters:
the journal uses `write` plus `fsync` so the durability point is explicit, and
message framing is hand-rolled (`send_all` loops on partial writes; `recv_line`
reads to a newline) because TCP provides a byte stream with no message
boundaries.
