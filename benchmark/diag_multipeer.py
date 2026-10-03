#!/usr/bin/env python3
"""One-off diagnostic: prove (or disprove) that a single download actually
opens concurrent connections to multiple distinct seeder processes, by
snapshotting the downloader's open TCP connections via `lsof` while a
multi-piece download is in flight. Not part of the benchmark suite."""

import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

bench.VERBOSE = False


def lsof_remote_ports(pid):
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-p", str(pid), "-a", "-i", "tcp"],
            capture_output=True, text=True, timeout=2,
        ).stdout
    except Exception:
        return set()
    ports = set()
    for line in out.splitlines()[1:]:
        # NAME column looks like 127.0.0.1:54321->127.0.0.1:20007 (ESTABLISHED)
        if "->" in line:
            remote = line.split("->")[1].split()[0]
            if ":" in remote:
                ports.add(remote.rsplit(":", 1)[1])
    return ports


def main():
    bench.build_binaries(skip_build=True)
    filesize_kb = 200 * 1024  # 200MB -> ~400 pieces, enough wall-clock time to observe
    testdir = bench.tempfile.mkdtemp(prefix="diag_testfile_")
    fname = "diagfile.bin"
    testfile = os.path.join(testdir, fname)
    print(f"[setup] generating {filesize_kb} KB test file")
    bench.make_test_file(testfile, filesize_kb)

    trackers, journal_dir = bench.start_trackers()
    run_tag = uuid.uuid4().hex[:8]
    gid = f"diag_{run_tag}"
    owner, _ = bench.setup_owner_seeder(gid, testfile, run_tag)
    seeder2, _ = bench.add_seeder(owner, gid, testfile, 0, run_tag)
    dl, _ = bench.add_downloader(owner, gid, 0, run_tag)

    print(f"[info] owner (seeder A) client pid={owner.proc.pid}, port={owner.port}")
    print(f"[info] seeder B          client pid={seeder2.proc.pid}, port={seeder2.port}")
    print(f"[info] downloader        client pid={dl.proc.pid}, port={dl.port}")

    destdir = bench.tempfile.mkdtemp(prefix="diag_dest_")
    destpath = os.path.join(destdir, fname)

    dl.proc.stdin.write(f"download_file {gid} {fname} {destpath}\n".encode())
    dl.proc.stdin.flush()

    observed_remote_ports = set()
    port_combo_seen = set()  # snapshots where >1 distinct seeder port appeared at once
    t0 = time.perf_counter()
    samples = 0
    # poll lsof back-to-back (no sleep) for a generous fixed window; check
    # completion separately afterward so this loop's cadence is undisturbed
    while time.perf_counter() - t0 < 25:
        snap = lsof_remote_ports(dl.proc.pid)
        samples += 1
        observed_remote_ports |= snap
        seeder_ports_now = snap & {str(owner.port), str(seeder2.port)}
        if len(seeder_ports_now) > 1:
            port_combo_seen.add(frozenset(seeder_ports_now))
        if samples % 25 == 0:
            out = dl.cmd("show_downloads", timeout=5)
            if f"[C] [{gid}] {fname}" in out:
                break
            if f"[F] [{gid}] {fname}" in out:
                print("[error] download failed:", out)
                break
    print(f"[info] took {samples} lsof samples over {time.perf_counter()-t0:.2f}s")

    print()
    print("=== Result ===")
    print(f"Seeder A (owner) peer port : {owner.port}")
    print(f"Seeder B          peer port: {seeder2.port}")
    print(f"Remote ports the downloader connected to during transfer: {sorted(observed_remote_ports)}")

    hit_a = str(owner.port) in observed_remote_ports
    hit_b = str(seeder2.port) in observed_remote_ports
    if port_combo_seen:
        print("=> CONFIRMED: caught at least one instant where the downloader had "
              "OPEN, SIMULTANEOUS TCP connections to BOTH seeder ports at once "
              f"(e.g. {sorted(next(iter(port_combo_seen)))}). This is genuine "
              "concurrent multi-peer transfer, not sequential/fake.")
    elif hit_a and hit_b:
        print("=> Connected to BOTH seeders over the course of the download, but "
              "never caught them open at the exact same polled instant (connections "
              "are short-lived per piece -- true simultaneity is easy to miss by "
              "polling from outside). Still real evidence both peers were used.")
    elif hit_a or hit_b:
        print("=> Only observed ONE of the two seeders during this run.")
    else:
        print("=> Did not observe any connection to either seeder port -- "
              "polling likely missed the whole transfer window.")

    dl.quit()
    seeder2.quit()
    owner.quit()
    bench.stop_trackers(trackers, journal_dir)
    bench.shutil.rmtree(testdir, ignore_errors=True)
    bench.shutil.rmtree(destdir, ignore_errors=True)


if __name__ == "__main__":
    main()
