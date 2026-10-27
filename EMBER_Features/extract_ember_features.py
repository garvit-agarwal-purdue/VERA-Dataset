#!/usr/bin/env python3
"""Generate EMBER2024 (thrember, feature version 3) features for the VERA dataset.

Subcommands:
  extract    compute raw features -> raw_features.jsonl (+ failures.csv, run_info.json)
  vectorize  turn raw_features.jsonl into X_vera.dat + index.csv

SAFETY: binaries are live ransomware. They are only read as bytes and parsed
statically by thrember/pefile. Nothing is executed, copied, moved or modified.
Run with `python -I` so nothing is imported from the current directory.
"""
import argparse
import csv
import datetime as dt
import json
import os
import signal
import sys
import time
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from concurrent.futures.process import BrokenProcessPool

THREMBER_COMMIT = "0ef753e81d98bf209f71b03cd331dfc190b5b54d"
FEATURE_VERSION = 3  # "EMBER feature version 3" (thrember)
FAIL_FIELDS = ["sha256", "partition", "error_type", "error_message"]

_extractor = None


def import_thrember():
    """Import thrember. oscrypto 1.3.0 (pulled in by signify) cannot parse OpenSSL 3.0.x version
    strings with a 2-digit patch (e.g. 3.0.15) and fails at import; if the system has
    libcrypto/libssl 1.1, point oscrypto at them before importing."""
    import glob
    lib = "/usr/lib/x86_64-linux-gnu"
    c, s = glob.glob(lib + "/libcrypto.so.1.1"), glob.glob(lib + "/libssl.so.1.1")
    if c and s:
        try:
            import oscrypto
            oscrypto.use_openssl(c[0], s[0])
        except Exception:
            pass
    import thrember
    return thrember


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _get_extractor():
    global _extractor
    if _extractor is None:
        _extractor = import_thrember().PEFeatureExtractor()
    return _extractor


def _alarm(signum, frame):
    raise TimeoutError("per-file timeout exceeded")


def _work(path, sha, partition, timeout):
    """Runs in a worker. Returns ('ok', sha, partition, raw_dict) or ('fail', sha, partition, (type, msg))."""
    try:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(timeout)
        try:
            with open(path, "rb") as f:  # read-only, bytes only
                data = f.read()
            raw = _get_extractor().raw_features(data)
        finally:
            signal.alarm(0)
        return ("ok", sha, partition, raw)
    except BaseException as e:  # noqa: BLE001 - never let one file kill the worker
        return ("fail", sha, partition, (type(e).__name__, str(e)[:500]))


def load_families(labels_dir):
    """sha256 -> (family, label_source). Label_Source column is optional."""
    fam = {}
    p = os.path.join(labels_dir, "Final_Family_Labels.csv")
    if os.path.isfile(p):
        with open(p, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                fam[r["SHA256"].strip().lower()] = (r.get("Final_Family") or None, r.get("Label_Source") or None)
    return fam


def partition_name(d):
    b = os.path.basename(os.path.normpath(d))
    return b[5:] if b.startswith("VERA-") else b


def sha_from_name(fn):
    return (fn[:-4] if fn.endswith(".bin") else fn).lower()


def read_done(out_dir, retry_failed):
    done = set()
    raw = os.path.join(out_dir, "raw_features.jsonl")
    if os.path.isfile(raw):
        with open(raw, encoding="utf-8") as f:
            for line in f:
                try:
                    o = json.loads(line)
                    done.add((o["vera_sha256"], o["vera_partition"]))
                except Exception:
                    pass  # truncated last line from an interrupted run
    fp = os.path.join(out_dir, "failures.csv")
    if os.path.isfile(fp) and not retry_failed:
        with open(fp, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                done.add((r["sha256"], r["partition"]))
    return done


def cmd_extract(a):
    out = os.path.abspath(a.out_dir)
    os.makedirs(out, exist_ok=True)
    fams = load_families(a.labels_dir)
    done = read_done(out, a.retry_failed)
    t_start = _now()
    t0 = time.time()

    todo = []
    for d in a.binaries_dir:
        part = partition_name(d)
        names = sorted(os.listdir(d))
        if a.limit:
            names = names[: a.limit]
        for fn in names:
            sha = sha_from_name(fn)
            if (sha, part) not in done:
                todo.append((os.path.join(d, fn), sha, part))
    print(f"[extract] {len(todo)} files to process ({len(done)} already done)", flush=True)

    fail_path = os.path.join(out, "failures.csv")
    new_fail = not os.path.isfile(fail_path) or os.path.getsize(fail_path) == 0
    n_ok = n_fail = n_mismatch = 0
    fail_types = {}

    def handle(res, fout, ffail, fw):
        nonlocal n_ok, n_fail, n_mismatch
        kind, sha, part, payload = res
        if kind == "ok":
            fam, src = fams.get(sha, (None, None)) if part == "Active" else (None, None)
            if payload.get("sha256") != sha:
                n_mismatch += 1
            payload["vera_sha256"] = sha
            payload["vera_partition"] = part
            payload["vera_family"] = fam
            payload["vera_label_source"] = src
            fout.write(json.dumps(payload) + "\n")
            fout.flush()
            n_ok += 1
        else:
            fw.writerow([sha, part, payload[0], payload[1]])
            ffail.flush()
            n_fail += 1
            fail_types[payload[0]] = fail_types.get(payload[0], 0) + 1

    with open(os.path.join(out, "raw_features.jsonl"), "a", encoding="utf-8") as fout, \
            open(fail_path, "a", newline="", encoding="utf-8") as ffail:
        fw = csv.writer(ffail)
        if new_fail:
            fw.writerow(FAIL_FIELDS)
        i = 0
        total = len(todo)
        while i < total:
            pool = ProcessPoolExecutor(max_workers=a.workers)
            pending = {}
            try:
                while i < total or pending:
                    while i < total and len(pending) < a.workers * 3:
                        job = todo[i]
                        pending[pool.submit(_work, job[0], job[1], job[2], a.timeout)] = job
                        i += 1
                    finished, _ = wait(list(pending), return_when=FIRST_COMPLETED)
                    for fut in finished:
                        job = pending.pop(fut)
                        try:
                            res = fut.result()
                        except BrokenProcessPool:
                            raise
                        except Exception as e:
                            res = ("fail", job[1], job[2], (type(e).__name__, str(e)[:500]))
                        handle(res, fout, ffail, fw)
                        k = n_ok + n_fail
                        if k % 500 == 0:
                            print(f"[extract] {k}/{total} ok={n_ok} fail={n_fail} "
                                  f"{(time.time()-t0)/k:.2f}s/file", flush=True)
            except BrokenProcessPool:
                # a worker died hard (OOM/segfault): record in-flight files, rebuild the pool, continue
                for fut, job in pending.items():
                    handle(("fail", job[1], job[2], ("WorkerCrash", "worker process died")), fout, ffail, fw)
                pending.clear()
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

    if not todo:
        print("[extract] nothing to do")
    else:
      write_run_info(out, a, t_start, time.time() - t0, n_ok, n_fail, fail_types, n_mismatch)
    k = max(n_ok + n_fail, 1)
    print(f"[extract] done: ok={n_ok} fail={n_fail} in {time.time()-t0:.1f}s ({(time.time()-t0)/k:.2f}s/file)")
    if a.vectorize:
        cmd_vectorize(a)


def write_run_info(out, a, t_start, secs, n_ok, n_fail, fail_types, n_mismatch):
    ex = import_thrember().PEFeatureExtractor()
    counts, nonpe = {}, {}
    with open(os.path.join(out, "raw_features.jsonl"), encoding="utf-8") as f:
        for line in f:
            try:
                o = json.loads(line)
            except Exception:
                continue
            p = o["vera_partition"]
            counts[p] = counts.get(p, 0) + 1
            if not o["general"]["is_pe"]:
                nonpe[p] = nonpe.get(p, 0) + 1
    fails = {}
    fp = os.path.join(out, "failures.csv")
    if os.path.isfile(fp):
        with open(fp, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                fails[r["partition"]] = fails.get(r["partition"], 0) + 1
    info = {
        "thrember_commit": THREMBER_COMMIT,
        "feature_version": FEATURE_VERSION,
        "vector_dim": ex.dim,
        "counts_per_partition": counts,
        "non_pe_per_partition": nonpe,
        "failures_per_partition": fails,
        "this_run": {"started": t_start, "finished": _now(), "seconds": round(secs, 1),
                     "ok": n_ok, "failed": n_fail, "failure_types": fail_types,
                     "filename_vs_content_sha_mismatches": n_mismatch,
                     "binaries_dirs": [os.path.abspath(d) for d in a.binaries_dir],
                     "workers": a.workers, "timeout_s": a.timeout, "limit": a.limit},
        "last_updated": _now(),
    }
    with open(os.path.join(out, "run_info.json"), "w") as f:
        json.dump(info, f, indent=2)


def cmd_vectorize(a):
    """Vectorize with EMBER's own PEFeatureExtractor.process_raw_features (as thrember.vectorize does)."""
    import numpy as np
    thrember = import_thrember()
    out = os.path.abspath(a.out_dir)
    ex = thrember.PEFeatureExtractor()
    raw = os.path.join(out, "raw_features.jsonl")
    n = sum(1 for _ in open(raw, encoding="utf-8"))
    X = np.memmap(os.path.join(out, "X_vera.dat"), dtype=np.float32, mode="w+", shape=(n, ex.dim))
    with open(os.path.join(out, "index.csv"), "w", newline="", encoding="utf-8") as fi:
        w = csv.writer(fi)
        w.writerow(["row", "sha256", "partition", "family", "label_source", "is_pe"])
        row = 0
        for line in open(raw, encoding="utf-8"):
            o = json.loads(line)
            if row >= n:
                break
            X[row] = ex.process_raw_features(o)
            w.writerow([row, o["vera_sha256"], o["vera_partition"], o.get("vera_family") or "",
                        o.get("vera_label_source") or "", o["general"]["is_pe"]])
            row += 1
    X.flush()
    print(f"[vectorize] wrote {row} x {ex.dim} float32 -> X_vera.dat, index.csv")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract", help="compute raw EMBER2024 features")
    e.add_argument("--binaries-dir", action="append", required=True, help="repeatable; partition = folder name minus 'VERA-'")
    e.add_argument("--labels-dir", required=True)
    e.add_argument("--out-dir", default="EMBER_Features/output")
    e.add_argument("--workers", type=int, default=8)
    e.add_argument("--limit", type=int, default=0, help="max files per folder (testing)")
    e.add_argument("--timeout", type=int, default=120, help="per-file timeout seconds")
    e.add_argument("--retry-failed", action="store_true", help="re-attempt files listed in failures.csv")
    e.add_argument("--vectorize", action="store_true", help="also run vectorize afterwards")
    v = sub.add_parser("vectorize", help="vectorize raw_features.jsonl -> X_vera.dat + index.csv")
    v.add_argument("--out-dir", default="EMBER_Features/output")
    a = ap.parse_args()
    {"extract": cmd_extract, "vectorize": cmd_vectorize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
