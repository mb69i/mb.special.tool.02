#!/usr/bin/env python3
"""fim.py - small file integrity monitor. Stdlib only, Python 3.9+.

    python fim.py init /etc /usr/local/bin     # record a baseline
    python fim.py check                        # compare the tree against it
    python fim.py update                       # accept current state as the new baseline
    python fim.py watch -i 60                  # poll and report changes

Exit codes: 0 clean, 1 changes found, 2 error. Set FIM_KEY to seal the baseline
with an HMAC so edits to the baseline file itself are detected.
"""
import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
import time

CHUNK = 1 << 20
SKIP = ["*.pyc", "*.swp", "*.tmp", "*~", "__pycache__", ".git", "*.log"]
MARK = {"added": "+", "removed": "-", "modified": "M", "attrs": "A"}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb", buffering=0) as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def seal(records, keyed):
    """Fingerprint of the whole record set, so baseline tampering shows up."""
    blob = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    key = os.environ.get("FIM_KEY", "")
    if keyed and key:
        return hmac.new(key.encode(), blob, hashlib.sha256).hexdigest()
    return hashlib.sha256(blob).hexdigest()


def excluded(path, pats):
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p) for p in pats)


def walk(roots, pats, follow, errs):
    seen = set()
    for root in roots:
        root = os.path.abspath(root)
        if not os.path.lexists(root):
            errs.append(f"{root}: not found")
            continue
        if not os.path.isdir(root) or (os.path.islink(root) and not follow):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(
                root, followlinks=follow, onerror=lambda e: errs.append(str(e))):
            dirnames[:] = [d for d in dirnames if not excluded(os.path.join(dirpath, d), pats)]
            # a directory swapped for a symlink is a classic trick, so record those too
            names = filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
            for name in names:
                p = os.path.join(dirpath, name)
                if not excluded(p, pats) and p not in seen:
                    seen.add(p)
                    yield p


def record(path, algo, follow, old, fast):
    st = os.stat(path) if follow else os.lstat(path)
    r = {"size": st.st_size, "mtime": int(st.st_mtime), "mode": stat.S_IMODE(st.st_mode),
         "uid": st.st_uid, "gid": st.st_gid}
    if stat.S_ISLNK(st.st_mode):
        r["link"] = os.readlink(path)
        return r
    if not stat.S_ISREG(st.st_mode):
        r["kind"] = "special"
        return r
    if fast and old and old.get("size") == r["size"] and old.get("mtime") == r["mtime"] and "hash" in old:
        r["hash"] = old["hash"]
    else:
        r["hash"] = file_hash(path, algo)
    return r


def scan(roots, pats, algo, follow, fast, old):
    recs, errs = {}, []
    for p in walk(roots, pats, follow, errs):
        try:
            recs[p] = record(p, algo, follow, old.get(p), fast)
        except OSError as e:
            errs.append(f"{p}: {e.strerror or e}")
    return recs, errs


def compare(old, new):
    o, n = set(old), set(new)
    out = {"added": sorted(n - o), "removed": sorted(o - n), "modified": [], "attrs": []}
    for p in sorted(o & n):
        a, b = old[p], new[p]
        why = []
        if a.get("hash") != b.get("hash"):
            why.append("content")
            if a.get("mtime") == b.get("mtime"):
                why.append("mtime unchanged - timestamp preserved")
        if a.get("link") != b.get("link"):
            why.append(f"symlink {a.get('link')} -> {b.get('link')}")
        if a.get("kind") != b.get("kind"):
            why.append("file type")
        if why:
            out["modified"].append([p, "; ".join(why)])
            continue
        for k, label in (("mode", "mode"), ("uid", "owner"), ("gid", "group")):
            if a.get(k) != b.get(k):
                va, vb = (format(a[k], "04o"), format(b[k], "04o")) if k == "mode" else (a[k], b[k])
                why.append(f"{label} {va} -> {vb}")
        if why:
            out["attrs"].append([p, "; ".join(why)])
    return out


def load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        recs, meta = d["records"], d["meta"]
    except (OSError, ValueError, KeyError) as e:
        die(f"cannot read baseline {path}: {e}")
    want = seal(recs, meta.get("keyed", False))
    if meta.get("keyed") and not os.environ.get("FIM_KEY"):
        print("! baseline is sealed but FIM_KEY is unset - cannot verify it", file=sys.stderr)
    elif not hmac.compare_digest(want, meta.get("seal", "")):
        print(f"! baseline {path} does not match its own seal - it was edited outside this tool",
              file=sys.stderr)
    return recs, meta


def save(path, recs, meta):
    meta["keyed"] = bool(os.environ.get("FIM_KEY"))
    meta["seal"] = seal(recs, meta["keyed"])
    meta["saved"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"meta": meta, "records": recs}, f, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def report(diff, recs, errs, secs, limit):
    total = sum(len(v) for v in diff.values())
    print(f"\n== {len(recs)} files, {secs}s, {total} change(s) ==")
    for kind in ("added", "removed", "modified", "attrs"):
        items = diff[kind]
        for item in items[:limit]:
            p, why = (item, "") if isinstance(item, str) else item
            print(f"{MARK[kind]} {p}" + (f"  ({why})" if why else ""))
        if len(items) > limit:
            print(f"  ... and {len(items) - limit} more {kind}")
    for e in errs[:5]:
        print(f"! {e}", file=sys.stderr)
    if len(errs) > 5:
        print(f"! ... and {len(errs) - 5} more errors", file=sys.stderr)
    return total


def run_scan(a, old, meta):
    t0 = time.time()
    recs, errs = scan(meta["roots"], meta["skip"], meta["algo"], meta["follow"], a.fast, old)
    return recs, errs, round(time.time() - t0, 1)


def main():
    ap = argparse.ArgumentParser(description="Small file integrity monitor.")
    ap.add_argument("mode", choices=["init", "check", "update", "watch"])
    ap.add_argument("paths", nargs="*", help="files or directories (init only)")
    ap.add_argument("-b", "--baseline", default="fim-baseline.json", help="baseline file")
    ap.add_argument("-x", "--exclude", action="append", default=[],
                    help="extra glob to skip, repeatable (always skipped: " + " ".join(SKIP) + ")")
    ap.add_argument("--algo", default="sha256", help="hash algorithm (default sha256)")
    ap.add_argument("--follow", action="store_true", help="follow symlinks")
    ap.add_argument("--fast", action="store_true",
                    help="reuse the stored hash when size and mtime match (misses timestamp-preserving edits)")
    ap.add_argument("-i", "--interval", type=int, default=60, help="watch interval in seconds")
    ap.add_argument("-n", "--max", type=int, default=50, help="lines printed per category")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("-q", "--quiet", action="store_true", help="print nothing when clean")
    a = ap.parse_args()
    if a.algo not in hashlib.algorithms_available:
        die(f"unknown hash algorithm {a.algo}; try: sha256 sha512 blake2b md5")

    if a.mode == "init":
        if not a.paths:
            die("init needs at least one path")
        missing = [p for p in a.paths if not os.path.lexists(p)]
        if missing:
            die("not found: " + ", ".join(missing))
        meta = {"roots": [os.path.abspath(p) for p in a.paths], "skip": SKIP + a.exclude,
                "algo": a.algo, "follow": a.follow}
        recs, errs, secs = run_scan(a, {}, meta)
        save(a.baseline, recs, meta)
        print(f"baseline: {len(recs)} files in {secs}s -> {a.baseline}")
        for e in errs[:5]:
            print(f"! {e}", file=sys.stderr)
        return 0

    old, meta = load(a.baseline)
    meta["skip"] = meta["skip"] + a.exclude

    if a.mode in ("check", "update"):
        recs, errs, secs = run_scan(a, old, meta)
        diff = compare(old, recs)
        if a.json:
            print(json.dumps({"files": len(recs), "seconds": secs, "errors": errs, **diff}, indent=2))
            total = sum(len(v) for v in diff.values())
        elif a.quiet and not sum(len(v) for v in diff.values()):
            total = 0
        else:
            total = report(diff, recs, errs, secs, a.max)
        if a.mode == "update":
            save(a.baseline, recs, meta)
            print(f"baseline updated ({total} change(s) accepted)")
            return 0
        return 1 if total else 0

    while True:  # watch
        recs, errs, secs = run_scan(a, old, meta)
        diff = compare(old, recs)
        if sum(len(v) for v in diff.values()):
            print(time.strftime("[%H:%M:%S]"), end="")
            report(diff, recs, errs, secs, a.max)
            sys.stdout.flush()
        elif not a.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] clean ({len(recs)} files, {secs}s)", flush=True)
        old = recs  # already reported; only report each change once
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:  # piped into head, less, etc.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
