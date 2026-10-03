# Findings

A durable record of what has been investigated, what was wrong, and what is
still open — so none of it has to be rediscovered by re-running things.

Deliberately records **findings**, not run results. A line saying "86 tests
passed on some date" rots into a lie the moment the code changes. Instead:
every bug below names the test that now pins it, and `./run-tests.sh` re-verifies
everything in one command.

---

## Bugs found and fixed

### 1. Infinite loop in journal replay on a torn record

**Severity: high — the tracker would hang on startup, silently.**

The replay loop advances with `pos = eol + 1`. If the journal has no trailing
newline — exactly what a crash mid-append leaves — `find('\n')` returns
`string::npos`, so `pos` wraps round to `0`. The loop restarts from the
beginning and replays the journal endlessly. No error, no crash; the tracker
just never finishes booting.

The truncation step that removes the unterminated tail was the only thing
preventing it, which the code comment did not convey.

*Found by:* deliberately disabling truncation to check the journal tests would
notice. Instead of failing, the test binary hung.

*Fixed:* the loop now checks for `npos` and stops with a diagnostic
(`tracker.cpp`, `open_and_replay_journal`).

*Pinned by:* `tests/test_journal.cpp` — `torn record discarded and file
truncated`, plus `append after a torn record stays clean`. Verified by
disabling both truncation *and* the resize: that combination hung before the
guard and now exits in under a second.

### 2. Failover reconnected but never re-authenticated

**Severity: high — failover was broken for every authenticated command.**

A tracker session is keyed by the socket it was created on (`sessions[fd]`).
When a client's tracker died it reconnected to the surviving one correctly, but
that new socket was anonymous, so every authenticated command returned
`ERR login_required` until the user logged in again by hand.

*Found by:* the failover integration test — but only after the first version of
that test was corrected. It originally probed with `list_groups`, which has **no
login check**, so it passed without testing authentication at all.

*Fixed:* the reconnect path now replays the session token
(`reauth_after_reconnect()` in `client.cpp`), at all three reconnect sites.

*Pinned by:* `tests/test_integration.py` — `client survives tracker failover`.
Verified by removing the fix and watching the test fail again.

### 3. Logout reissued an already-revoked token

**Severity: medium — intermittent, and invisible where you would look.**

Session tokens signed only `username + expiry`. Logging out adds the presented
token to a revocation set. So `login → logout → login` **within the same
second** produced a byte-identical token — the one just revoked — and the new
session held a credential the tracker refused.

Nastier than it sounds: typed commands kept working, because those ride the
REPL's own already-authenticated socket. Only background threads, which open
their own connections, failed — so the client silently stopped announcing that
it held files. And since expiry has one-second granularity, it only reproduced
when both actions landed in the same second: fine when typing by hand, broken
when scripted.

*Fixed:* a 12-byte random nonce in the signed payload, so no two tokens are
identical regardless of timing.

*Also fixed alongside:* the client never handled `logout` at all — it only
intercepted `login`, so after logging out it still held the dead token, still
had `current_user` set, and still believed it was logged in, meaning its own
not-logged-in guards never fired.

### 4. Credentials crossed the network in cleartext

`login` and `create_user` sent the password as literal ASCII. PBKDF2 hashing
protects a stolen credential database; it does nothing for someone watching the
wire.

*Fixed:* TLS 1.2+ on client↔tracker connections, multiplexed onto the existing
port by inspecting the first byte with `MSG_PEEK` (`0x16` = TLS handshake,
`S` = `SYNC_INIT`) — a handshake must complete before reading, but a sync peer
is identified *by* reading.

*Verified:* a logging proxy between client and tracker captured 1,748 bytes; the
password appears nowhere in them, and the stream opens `16 03 01`.

### 5. The client held the plaintext password for the process lifetime

Because sessions were socket-bound, background threads had to replay the
password on their own connections — which also put a deliberately slow
100,000-iteration PBKDF2 on a routine path.

*Fixed:* stateless HMAC-signed session tokens. The password is used once at
login and discarded; re-authentication is a signature check.

### 6. Filenames containing spaces were unusable

Every protocol is whitespace-split, so `my holiday video.mp4` was torn into two
fields and the command failed.

*Fixed:* quote-aware command parsing for what the user types, and
percent-encoding for what goes on the wire (tracker commands, sync records, the
journal, and the peer protocol).

*Verified:* end to end with `"my holiday video.mp4"` — upload, `list_files`,
peer discovery and a multi-peer download, with the downloaded file's SHA-256
matching the source exactly.

### 7. Dead code and a duplicated protocol constant

Three never-called functions (`download_from_peer_sequential`,
`background_download_worker`, `handle_client`) — 266 lines — removed. The
512 KiB piece size had been redeclared across **seven** sites (three named
locals and four bare literals doing offset arithmetic); a single missed edit
would have silently desynced the wire protocol. Now one `PIECE_SIZE`.

---

## Corrections to earlier conclusions

Recorded because the wrong version was stated out loud at the time.

**`show_seeders` is NOT broken.** It was reported as returning an empty peer
list. It does not — the output was being filtered by a shell pattern
(`[a-z]+@`) that could not match a username containing a digit, such as `u1@`.
Re-checked directly: it lists seeders correctly, both immediately after an
upload and later. The integration suite uses it successfully.

**The multi-peer speedup is not a measurable number on this hardware.** Figures
of 1.5×, 1.45×, 1.70×, 1.87× and 1.42× were each stated at some point as the
gain from a second seeder. All came from the same experiment at increasing rigour.
The final position: the two- and four-seeder throughputs are stable (1–8% spread)
but the *single-seeder baseline* — the denominator — varies 74% run to run, almost
certainly OS page cache. So no ratio is quoted. See the README's benchmark
section for the full progression.

---

## Open — known, unfixed

| | Severity | Note |
|---|---|---|
| `authenticated` computed then ignored | low | The auto-upload path checks whether token auth succeeded, sets the flag, then sends `upload_file` regardless. The tracker still enforces auth, so it is not a security hole — but a failed auth yields a confusing `ERR login_required` and a wasted round trip instead of a clear diagnosis. This is what the `-Wunused-but-set-variable` warning has been reporting. |
| No download resume | medium | The `.part` file is reused but the `have[]` bitmap starts empty, so an interrupted 1 GB download refetches every piece. The verified data is on disk and thrown away. |
| Split-brain divergence | high, by design | Two trackers, no consensus. During a partition both accept conflicting writes and diverge permanently. Documented but **never reproduced in a test** — that would be the most interesting demo available. |
| Token revocation is per-tracker | inherent | Validation is a signature check with no lookup, so `logout` only adds the token to an in-memory set lost on restart. Expiry (12h) is the real bound. Same trade-off as a JWT. |
| Peer protocol unauthenticated | medium | Any host reaching a peer's port and guessing an owner and filename can pull pieces. Group membership is enforced by the tracker, never peer-to-peer. |
| Sync link plaintext | low | Carries PBKDF2 hashes rather than passwords. Left unencrypted because a sync connection has a concurrent reader and writer, and one `SSL` object cannot safely be shared between them. |
| `recv_line` reads one byte per syscall | low | Irrelevant for short replies, but the manifest carries a hash per piece — ~84 KB for a 1 GB file, so ~84,000 syscalls to read one line. |
| Group and user names cannot contain whitespace | low | Only filenames are percent-encoded. The same helpers would extend unchanged. |
| Deprecated OpenSSL API | low | The low-level `SHA1_Init`/`Update`/`Final` calls are deprecated in OpenSSL 3; `EVP_*` is supported. Accounts for 5 of the 8 remaining compiler warnings. |

---

## Verified behaviours

Each has a test that fails if the behaviour regresses.

**Journal** (`tests/test_journal.cpp`, 19 tests / 86 assertions) — replay
rebuilds users, groups, membership and file manifests; torn records are detected,
discarded and truncated off; appends land cleanly afterwards; duplicates are
idempotent and are not rewritten to disk; CRLF, blank, unknown and malformed
records are survived; a full crash-and-restart cycle reproduces state; an append
is readable through a fresh descriptor immediately.

**Integration** (`tests/test_integration.py`, 5 scenarios) — replication between
trackers; partial-share seeding advertising a peer mid-download; corrupt pieces
rejected (and a liar unable to deny service when an honest peer exists); a
download surviving a `SIGKILL`ed seeder; tracker failover keeping the client
authenticated.

### Mutation results for the journal suite

A passing suite proves nothing unless it can fail, so each test was checked by
breaking the code deliberately:

| Mutation | Result |
|---|---|
| Skip truncating the torn tail | caught — 6 assertions fail |
| Stop deduplicating identical records | caught — 2 assertions fail |
| Never reopen the journal for append | caught |
| Drop `wire_decode` on replayed filenames | caught |
| Remove the `npos` replay guard | *not* caught — unreachable while truncation works, so the mutation is equivalent, not a gap |

Two tests were rewritten because their first versions passed for the wrong
reason: the dedup test asserted on a `std::set` (which deduplicates by itself)
rather than on the file not growing, and the corrupt-piece test used
`stop_share` to isolate the liar, which deleted the manifest entirely so the
download failed on a parse error rather than on hash verification.

---

## Not testable here

- **`fsync` durability.** Whether bytes reached the platter is invisible to a
  test in the same process — the page cache serves the read either way. Proving
  it needs process-kill or block-layer fault injection.
- **Token expiry.** 12-hour TTL, with no way to inject a clock.
- **Any real-network claim.** Everything runs on loopback, where all peers share
  one disk, one set of cores and no latency. This is why no speedup ratio is
  quoted.
