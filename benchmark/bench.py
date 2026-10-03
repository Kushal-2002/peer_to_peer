#!/usr/bin/env python3
"""
bench.py -- P2P vs. centralized file-distribution benchmark.

Drives the REAL tracker/client binaries from this project (no source files
touched) to measure actual download times, then compares them against a
tiny standalone "centralized server" baseline implemented right here.

Two experiments:

  Experiment 1 (peer scaling): one downloader, varying number of seeders
  holding the same file. Shows whether P2P download time improves as more
  sources become available, vs. a centralized single-source transfer which
  cannot improve no matter how many "peers" exist.

  Experiment 2 (client scaling): a fixed small swarm of seeders, varying
  number of *simultaneous* downloaders. Shows how P2P throughput holds up
  under concurrent load, vs. a centralized single server whose one source
  of bandwidth gets divided across all simultaneous downloaders.

Everything runs over loopback on a single machine (matches the project's
own tracker_info.txt, which is 127.0.0.1:9000 / 127.0.0.1:9001), so this
measures relative behavior, not real-network numbers. That's a real
limitation, stated up front rather than hidden.

Usage:
    python3 bench.py                      # run everything with fast defaults
    python3 bench.py --filesize-kb 8192   # use an 8MB test file
    python3 bench.py --peer-counts 1,2,4,8
    python3 bench.py --downloader-counts 1,2,4
    python3 bench.py --skip-build         # reuse already-built binaries
    python3 bench.py -v                   # print raw client I/O (debugging)

Requires only the Python standard library.
"""

import argparse
import csv
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
TRACKER_DIR = os.path.join(PROJECT_ROOT, "tracker")
CLIENT_DIR = os.path.join(PROJECT_ROOT, "client")
TRACKER_BIN = os.path.join(TRACKER_DIR, "tracker")
CLIENT_BIN = os.path.join(CLIENT_DIR, "client")
TRACKER_INFO = os.path.join(TRACKER_DIR, "tracker_info.txt")

VERBOSE = False

# Polling granularity for download-completion detection, in seconds. Any
# measured duration carries up to this much error, so runs must be sized well
# above it for the numbers to mean anything.
POLL_INTERVAL_S = 0.005


def vprint(*a, **kw):
    if VERBOSE:
        print(*a, **kw, file=sys.stderr)


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def openssl_flags():
    """Compiler flags needed to link OpenSSL.

    Both binaries need it now: the client for its SHA-1 piece hashes, and the
    tracker for PBKDF2 password hashing. macOS ships no OpenSSL headers or libs
    and Homebrew's openssl is keg-only (not on the default include/lib path),
    so point the compiler at it explicitly.
    """
    flags = []
    if sys.platform == "darwin":
        prefix = None
        for pkg in ("openssl@3", "openssl"):
            try:
                out = subprocess.run(["brew", "--prefix", pkg],
                                      capture_output=True, text=True, check=True)
                prefix = out.stdout.strip()
                break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        if not prefix:
            raise RuntimeError(
                "Could not locate a Homebrew OpenSSL install (tried openssl@3, "
                "openssl). Install one with `brew install openssl@3` and retry."
            )
        flags += [f"-I{prefix}/include", f"-L{prefix}/lib"]
    return flags + ["-pthread", "-lssl", "-lcrypto"]


def build_binaries(skip_build: bool):
    if skip_build and os.path.exists(TRACKER_BIN) and os.path.exists(CLIENT_BIN):
        print("[build] --skip-build set and binaries exist, reusing them.")
        return
    ssl_flags = openssl_flags()
    print("[build] compiling tracker ...")
    subprocess.run(
        ["g++", "-std=gnu++17", "-O2", "-Wall", "-Wextra", "tracker.cpp",
         "-o", "tracker"] + ssl_flags,
        cwd=TRACKER_DIR, check=True,
    )
    print("[build] compiling client ...")
    subprocess.run(
        ["g++", "-std=gnu++17", "-O2", "-Wall", "-Wextra", "client.cpp",
         "-o", "client"] + ssl_flags,
        cwd=CLIENT_DIR, check=True,
    )
    print("[build] done.")


# --------------------------------------------------------------------------
# Tracker process management
# --------------------------------------------------------------------------

def start_trackers():
    """Start every tracker listed in tracker_info.txt on a clean journal.

    The tracker persists its operation log and replays it on startup, so
    reusing the default journal path would carry the previous run's users,
    groups and (now dead) seeder entries into this one. A throwaway journal
    directory per run keeps each measurement independent.
    """
    with open(TRACKER_INFO) as f:
        n = len([l for l in f if l.strip()])
    journal_dir = tempfile.mkdtemp(prefix="bench_journals_")
    procs = []
    for i in range(n):
        journal = os.path.join(journal_dir, f"tracker_{i}.journal")
        p = subprocess.Popen(
            [TRACKER_BIN, TRACKER_INFO, str(i), journal],
            cwd=TRACKER_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL if not VERBOSE else None,
            stderr=subprocess.DEVNULL if not VERBOSE else None,
        )
        procs.append(p)
    time.sleep(1.5)  # let them bind + connect to each other
    for p in procs:
        if p.poll() is not None:
            shutil.rmtree(journal_dir, ignore_errors=True)
            raise RuntimeError(f"tracker instance failed to start (exit code {p.returncode}); "
                                f"is a previous run's tracker still holding the port?")
    print(f"[trackers] {n} tracker instance(s) started, journals in {journal_dir}")
    return procs, journal_dir


def stop_trackers(procs, journal_dir=None):
    for p in procs:
        try:
            p.stdin.write(b"quit\n")
            p.stdin.flush()
        except Exception:
            pass
    time.sleep(0.3)
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    if journal_dir:
        shutil.rmtree(journal_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# Client process driver
# --------------------------------------------------------------------------

class ClientProc:
    """Drives one `client` subprocess through its interactive '> ' prompt."""

    def __init__(self, port, label):
        self.port = port
        self.label = label
        self.workdir = tempfile.mkdtemp(prefix=f"bench_client_{label}_")
        # Each client runs in its own scratch directory so their client.log
        # files don't collide, which means the tracker's certificate is not on
        # their relative path. Point them at it explicitly so the tracker
        # connection is verified rather than falling back to unverified TLS.
        env = os.environ.copy()
        ca = os.path.join(CLIENT_DIR, "server.crt")
        if os.path.exists(ca):
            env["TRACKER_TLS_CA"] = ca
        self.proc = subprocess.Popen(
            [CLIENT_BIN, f"127.0.0.1:{port}", TRACKER_INFO],
            cwd=self.workdir,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if not VERBOSE else None,
        )
        self._buf = ""
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        # consume the startup banner up through the first "> " prompt
        self._wait_for_prompt(timeout=15)

    def _read_loop(self):
        fd = self.proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            with self._lock:
                self._buf += chunk.decode(errors="replace")

    def _wait_for_prompt(self, timeout=30):
        """Return output up to and including the next '> ' prompt.

        The client's download workers print '[piece n/m] <- peer' from
        background threads, so the prompt is very often *not* the last thing in
        the buffer -- async progress lines land after it. Waiting for the buffer
        to end with the prompt therefore deadlocks on any file big enough to
        have several pieces. Split at the first prompt instead and keep the
        remainder for the next call.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                i = self._buf.find("> ")
                if i != -1:
                    out = self._buf[:i + 2]
                    self._buf = self._buf[i + 2:]
                    return out
            time.sleep(0.005)
        with self._lock:
            partial = self._buf
        raise TimeoutError(f"[{self.label}] timed out waiting for prompt; buffer so far: {partial!r}")

    def cmd(self, line, timeout=30):
        vprint(f"[{self.label}] >>> {line}")
        self.proc.stdin.write((line + "\n").encode())
        self.proc.stdin.flush()
        out = self._wait_for_prompt(timeout=timeout)
        vprint(f"[{self.label}] <<< {out!r}")
        return out

    def quit(self):
        try:
            self.proc.stdin.write(b"quit\n")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.workdir, ignore_errors=True)


_port_counter = [20000]
_port_lock = threading.Lock()


def next_port():
    with _port_lock:
        _port_counter[0] += 1
        return _port_counter[0]


# --------------------------------------------------------------------------
# Test-file generation
# --------------------------------------------------------------------------

def make_test_file(path, size_kb):
    with open(path, "wb") as f:
        remaining = size_kb * 1024
        chunk = os.urandom(min(remaining, 1024 * 1024))
        while remaining > 0:
            n = min(len(chunk), remaining)
            f.write(chunk[:n])
            remaining -= n


# --------------------------------------------------------------------------
# P2P swarm helpers
# --------------------------------------------------------------------------

def setup_owner_seeder(gid, filepath, run_tag):
    user = f"owner_{run_tag}"
    c = ClientProc(next_port(), f"owner-{run_tag}")
    assert "OK" in c.cmd(f"create_user {user} pw")
    assert "OK" in c.cmd(f"login {user} pw")
    assert "OK" in c.cmd(f"create_group {gid}")
    r = c.cmd(f"upload_file {gid} {filepath}")
    assert "OK" in r, f"owner upload failed: {r}"
    return c, user


def add_seeder(owner: ClientProc, gid, filepath, idx, run_tag):
    user = f"seed{idx}_{run_tag}"
    c = ClientProc(next_port(), f"seed{idx}-{run_tag}")
    c.cmd(f"create_user {user} pw")
    c.cmd(f"login {user} pw")
    c.cmd(f"join_group {gid}")
    assert "OK" in owner.cmd(f"accept_request {gid} {user}")
    r = c.cmd(f"upload_file {gid} {filepath}")
    assert "OK" in r, f"seeder {idx} upload failed: {r}"
    return c, user


def add_downloader(owner: ClientProc, gid, idx, run_tag):
    user = f"dl{idx}_{run_tag}"
    c = ClientProc(next_port(), f"dl{idx}-{run_tag}")
    c.cmd(f"create_user {user} pw")
    c.cmd(f"login {user} pw")
    c.cmd(f"join_group {gid}")
    assert "OK" in owner.cmd(f"accept_request {gid} {user}")
    return c, user


def timed_p2p_download(dl: ClientProc, gid, fname, destpath, timeout=120):
    t0 = time.perf_counter()
    r = dl.cmd(f"download_file {gid} {fname} {destpath}")
    assert "OK download_started" in r, f"download_file rejected: {r}"
    tag_re = re.compile(r"\[(.)\]\s*\[" + re.escape(gid) + r"\]\s*" + re.escape(fname))
    while True:
        out = dl.cmd("show_downloads")
        m = tag_re.search(out)
        if m:
            tag = m.group(1)
            if tag == "C":
                return time.perf_counter() - t0
            if tag == "F":
                raise RuntimeError(f"download failed: {out}")
        if time.perf_counter() - t0 > timeout:
            raise TimeoutError(f"download did not finish within {timeout}s; last show_downloads: {out}")
        # Completion is detected by polling, so this interval is the floor on
        # the error of every timing below it. Keep it well under the shortest
        # download being measured.
        time.sleep(POLL_INTERVAL_S)


# --------------------------------------------------------------------------
# Centralized baseline (single-source server, not part of the P2P system)
# --------------------------------------------------------------------------

class CentralizedServer:
    """Naive single-source file server: one listening socket, thread per
    connection, streams the whole file sequentially. This is the
    'centralized file transfer model' the assignment asks to compare
    against -- no chunking, no multi-source parallelism."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        self.sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            with open(self.filepath, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    conn.sendall(chunk)
        finally:
            conn.close()

    def stop(self):
        self._stop = True
        self.sock.close()


def timed_centralized_download(server_port, dest_path, expected_size, timeout=120):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", server_port))
    got = 0
    with open(dest_path, "wb") as f:
        while got < expected_size:
            chunk = s.recv(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
    s.close()
    elapsed = time.perf_counter() - t0
    if got != expected_size:
        raise RuntimeError(f"centralized transfer incomplete: got {got} of {expected_size} bytes")
    return elapsed


# --------------------------------------------------------------------------
# Experiments
# --------------------------------------------------------------------------

def experiment_peer_scaling(testfile, fname, filesize, peer_counts, repeat, results):
    print("\n=== Experiment 1: peer scaling (1 downloader, varying #seeders) ===")
    for n_seeders in peer_counts:
        for trial in range(repeat):
            run_tag = uuid.uuid4().hex[:8]
            gid = f"exp1_{n_seeders}s_{run_tag}"
            owner, _ = setup_owner_seeder(gid, testfile, run_tag)
            extra_seeders = []
            try:
                for i in range(n_seeders - 1):
                    extra_seeders.append(add_seeder(owner, gid, testfile, i, run_tag))
                dl, _dl_user = add_downloader(owner, gid, 0, run_tag)
                destdir = tempfile.mkdtemp(prefix="bench_dest_")
                destpath = os.path.join(destdir, fname)
                try:
                    elapsed = timed_p2p_download(dl, gid, fname, destpath)
                    throughput = filesize / elapsed / (1024 * 1024)
                    print(f"  seeders={n_seeders:2d} trial={trial}  time={elapsed:6.3f}s  "
                          f"throughput={throughput:6.2f} MB/s")
                    results.append({
                        "experiment": "peer_scaling", "seeders": n_seeders,
                        "downloaders": 1, "trial": trial,
                        "filesize_kb": filesize // 1024, "seconds": elapsed,
                        "mb_per_s": throughput,
                    })
                finally:
                    shutil.rmtree(destdir, ignore_errors=True)
                dl.quit()
            finally:
                for c, _ in extra_seeders:
                    c.quit()
                owner.quit()


def experiment_client_scaling(testfile, fname, filesize, seeder_count, downloader_counts, repeat, results):
    print(f"\n=== Experiment 2: client scaling (fixed {seeder_count} seeders, "
          "varying #simultaneous downloaders) ===")
    for n_dl in downloader_counts:
        for trial in range(repeat):
            run_tag = uuid.uuid4().hex[:8]
            gid = f"exp2_{n_dl}d_{run_tag}"
            owner, _ = setup_owner_seeder(gid, testfile, run_tag)
            extra_seeders = []
            downloaders = []
            destdirs = []
            try:
                for i in range(seeder_count - 1):
                    extra_seeders.append(add_seeder(owner, gid, testfile, i, run_tag))
                for i in range(n_dl):
                    downloaders.append(add_downloader(owner, gid, i, run_tag))

                results_times = [None] * n_dl
                errors = [None] * n_dl

                def worker(i, dl):
                    destdir = tempfile.mkdtemp(prefix="bench_dest_")
                    destdirs.append(destdir)
                    destpath = os.path.join(destdir, f"{i}_{fname}")
                    try:
                        results_times[i] = timed_p2p_download(dl, gid, fname, destpath)
                    except Exception as e:
                        errors[i] = e

                threads = [threading.Thread(target=worker, args=(i, dl)) for i, (dl, _) in enumerate(downloaders)]
                t_start = time.perf_counter()
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                wall = time.perf_counter() - t_start

                for i, e in enumerate(errors):
                    if e:
                        raise e
                avg = sum(results_times) / len(results_times)
                print(f"  downloaders={n_dl:2d} trial={trial}  "
                      f"avg_individual={avg:6.3f}s  wall_clock_all_done={wall:6.3f}s")
                results.append({
                    "experiment": "client_scaling_p2p", "seeders": seeder_count,
                    "downloaders": n_dl, "trial": trial,
                    "filesize_kb": filesize // 1024, "seconds": avg,
                    "mb_per_s": filesize / avg / (1024 * 1024),
                    "wall_clock_all": wall,
                })
            finally:
                for c, _ in downloaders:
                    c.quit()
                for c, _ in extra_seeders:
                    c.quit()
                owner.quit()
                for d in destdirs:
                    shutil.rmtree(d, ignore_errors=True)


def experiment_centralized(testfile, filesize, downloader_counts, repeat, results):
    print("\n=== Centralized baseline (single naive server, varying "
          "#simultaneous downloaders) ===")
    server = CentralizedServer(testfile)
    try:
        for n_dl in downloader_counts:
            for trial in range(repeat):
                destdirs = []
                results_times = [None] * n_dl
                errors = [None] * n_dl

                def worker(i):
                    destdir = tempfile.mkdtemp(prefix="bench_central_dest_")
                    destdirs.append(destdir)
                    destpath = os.path.join(destdir, f"{i}_central.bin")
                    try:
                        results_times[i] = timed_centralized_download(server.port, destpath, filesize)
                    except Exception as e:
                        errors[i] = e

                threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_dl)]
                t_start = time.perf_counter()
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                wall = time.perf_counter() - t_start

                for e in errors:
                    if e:
                        raise e
                avg = sum(results_times) / len(results_times)
                print(f"  downloaders={n_dl:2d} trial={trial}  "
                      f"avg_individual={avg:6.3f}s  wall_clock_all_done={wall:6.3f}s")
                results.append({
                    "experiment": "client_scaling_centralized", "seeders": 1,
                    "downloaders": n_dl, "trial": trial,
                    "filesize_kb": filesize // 1024, "seconds": avg,
                    "mb_per_s": filesize / avg / (1024 * 1024),
                    "wall_clock_all": wall,
                })
                for d in destdirs:
                    shutil.rmtree(d, ignore_errors=True)
    finally:
        server.stop()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def parse_int_list(s):
    return [int(x) for x in s.split(",") if x.strip()]


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filesize-kb", type=int, default=2048,
                     help="test file size in KB (default 2048 = 2MB)")
    ap.add_argument("--peer-counts", type=str, default="1,2,4",
                     help="comma-separated seeder counts for Experiment 1")
    ap.add_argument("--downloader-counts", type=str, default="1,2,4",
                     help="comma-separated concurrent-downloader counts for Experiment 2")
    ap.add_argument("--seeder-count-exp2", type=int, default=2,
                     help="fixed number of seeders used in Experiment 2")
    ap.add_argument("--repeat", type=int, default=1, help="repetitions per data point")
    ap.add_argument("--skip-build", action="store_true", help="reuse existing binaries")
    ap.add_argument("--results", type=str, default=os.path.join(HERE, "results.csv"),
                     help="where to write the CSV of raw results")
    ap.add_argument("-v", "--verbose", action="store_true", help="print raw client I/O")
    args = ap.parse_args()
    VERBOSE = args.verbose

    peer_counts = parse_int_list(args.peer_counts)
    downloader_counts = parse_int_list(args.downloader_counts)
    filesize = args.filesize_kb * 1024

    build_binaries(args.skip_build)

    testdir = tempfile.mkdtemp(prefix="bench_testfile_")
    fname = "benchfile.bin"
    testfile = os.path.join(testdir, fname)
    print(f"[setup] generating {args.filesize_kb} KB test file at {testfile}")
    make_test_file(testfile, args.filesize_kb)

    tracker_procs, journal_dir = start_trackers()
    results = []
    try:
        experiment_peer_scaling(testfile, fname, filesize, peer_counts, args.repeat, results)
        experiment_client_scaling(testfile, fname, filesize, args.seeder_count_exp2,
                                   downloader_counts, args.repeat, results)
        experiment_centralized(testfile, filesize, downloader_counts, args.repeat, results)
    finally:
        stop_trackers(tracker_procs, journal_dir)
        shutil.rmtree(testdir, ignore_errors=True)

    if results:
        with open(args.results, "w", newline="") as f:
            fieldnames = sorted({k for r in results for k in r})
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(results)
        print(f"\n[done] wrote {len(results)} rows to {args.results}")

    print_summary(results)


def print_summary(results):
    print("\n=== Summary ===")
    print(f"{'experiment':<26} {'seeders':>7} {'dlers':>6} {'sizeKB':>8} "
          f"{'avg_s':>8} {'MB/s':>7}")
    from collections import defaultdict
    grouped = defaultdict(list)
    for r in results:
        key = (r["experiment"], r["seeders"], r["downloaders"], r["filesize_kb"])
        grouped[key].append(r["seconds"])
    for key in sorted(grouped):
        exp, seeders, dlers, sizekb = key
        times = grouped[key]
        avg = sum(times) / len(times)
        mbps = (sizekb * 1024 / avg) / (1024 * 1024)
        print(f"{exp:<26} {seeders:>7} {dlers:>6} {sizekb:>8} {avg:>8.3f} {mbps:>7.2f}")


if __name__ == "__main__":
    main()
